use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
