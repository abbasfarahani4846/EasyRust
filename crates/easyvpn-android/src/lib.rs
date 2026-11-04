pub mod qr;

#[cfg(target_os = "android")]
mod android {
    use anyhow::{anyhow, bail, Context, Result};
    use easyvpn_gui::{Platform, VpnStatus};
    use jni::{
        jni_sig, jni_str,
        objects::{JByteArray, JClass, JObject, JString},
        refs::Global,
        sys::{jint, jstring},
        Env, EnvUnowned, JValue, JavaVM,
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        panic::{catch_unwind, AssertUnwindSafe},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, MutexGuard, OnceLock,
        },
        thread::JoinHandle,
    };
    use tun2proxy::{ArgDns, Args, CancellationToken, ProxyParameters};
    use winit::platform::android::activity::AndroidApp;

    static VPN_STATUS: OnceLock<Mutex<VpnStatus>> = OnceLock::new();
    static TUN: OnceLock<Mutex<Option<TunWorker>>> = OnceLock::new();
    static QR_RESULT: OnceLock<Mutex<Option<std::result::Result<String, String>>>> = OnceLock::new();
    static BACK_PRESSED: AtomicBool = AtomicBool::new(false);
    type Wake = Arc<dyn Fn() + Send + Sync>;
    static WAKE: OnceLock<Mutex<Option<Wake>>> = OnceLock::new();

    fn wake() -> &'static Mutex<Option<Wake>> {
        WAKE.get_or_init(|| Mutex::new(None))
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn status() -> &'static Mutex<VpnStatus> {
        VPN_STATUS.get_or_init(|| Mutex::new(VpnStatus::Idle))
    }

    fn set_status(value: VpnStatus) {
        *lock(status()) = value;
    }

    fn qr_result() -> &'static Mutex<Option<std::result::Result<String, String>>> {
        QR_RESULT.get_or_init(|| Mutex::new(None))
    }

    struct TunWorker {
        cancel: CancellationToken,
        thread: JoinHandle<()>,
    }

    fn tun_slot() -> &'static Mutex<Option<TunWorker>> {
        TUN.get_or_init(|| Mutex::new(None))
    }

    fn stop_tun() {
        // Java must keep the borrowed descriptor open until the worker stops.
        let mut slot = lock(tun_slot());
        if let Some(worker) = slot.take() {
            worker.cancel.cancel();
            if worker.thread.join().is_err() {
                log::error!("TUN worker panicked");
            }
        }
    }

    fn string_object(env: &Env<'_>, object: &JObject<'_>) -> Result<String> {
        if object.as_raw().is_null() {
            bail!("Java returned a null string");
        }
        // SAFETY: Callers pass objects declared as java.lang.String. The local
        // reference remains live in the current JNI frame.
        let string = unsafe { JString::from_raw(env, object.as_raw()) };
        Ok(string.try_to_string(env)?)
    }

    pub struct AndroidPlatform {
        vm: JavaVM,
        activity: Global<JObject<'static>>,
        insets: (f32, f32),
    }

    impl AndroidPlatform {
        /// Called while AndroidApp's VM and activity references are live.
        unsafe fn new(app: &AndroidApp) -> Result<Self> {
            // SAFETY: AndroidApp owns this VM for the application lifetime.
            let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) };
            let (activity, insets) = vm.attach_current_thread(|env: &mut Env| -> Result<_> {
                // SAFETY: Retain AndroidApp's live activity in this JNI frame.
                let local = unsafe { JObject::from_raw(env, app.activity_as_ptr().cast()) };
                let activity = env.new_global_ref(&local)?;
                let insets = read_insets(env, &local).unwrap_or_else(|error| {
                    log::warn!("Could not read system bar insets: {error:#}");
                    (0.0, 0.0)
                });
                Ok((activity, insets))
            })?;
            Ok(Self { vm, activity, insets })
        }

        fn with_env<T>(
            &self,
            callback: impl FnOnce(&mut Env, &JObject<'static>) -> Result<T>,
        ) -> Result<T> {
            self.vm
                .attach_current_thread(|env: &mut Env| callback(env, self.activity.as_ref()))
        }
    }

    impl Drop for AndroidPlatform {
        fn drop(&mut self) {
            self.stop_vpn();
        }
    }

    impl Platform for AndroidPlatform {
        fn is_mobile(&self) -> bool {
            true
        }

        fn clipboard_get(&self) -> Option<String> {
            self.with_env(|env, activity| {
                let service = env.new_string("clipboard")?;
                let manager = env.call_method(
                    activity,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&service)],
                )?.l()?;
                if manager.as_raw().is_null() {
                    bail!("Android clipboard is unavailable");
                }
                let clip = env.call_method(
                    &manager,
                    jni_str!("getPrimaryClip"),
                    jni_sig!("()Landroid/content/ClipData;"),
                    &[],
                )?.l()?;
                if clip.as_raw().is_null() {
                    return Ok(None);
                }
                let count = env.call_method(
                    &clip, jni_str!("getItemCount"), jni_sig!("()I"), &[],
                )?.i()?;
                if count == 0 {
                    return Ok(None);
                }
                let item = env.call_method(
                    &clip,
                    jni_str!("getItemAt"),
                    jni_sig!("(I)Landroid/content/ClipData$Item;"),
                    &[JValue::Int(0)],
                )?.l()?;
                let text = env.call_method(
                    &item,
                    jni_str!("coerceToText"),
                    jni_sig!("(Landroid/content/Context;)Ljava/lang/CharSequence;"),
                    &[JValue::Object(activity)],
                )?.l()?;
                if text.as_raw().is_null() {
                    return Ok(None);
                }
                let string = env.call_method(
                    &text,
                    jni_str!("toString"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?.l()?;
                Ok(Some(string_object(env, &string)?))
            }).unwrap_or_else(|error| {
                log::warn!("Clipboard read failed: {error:#}");
                None
            })
        }

        fn clipboard_set(&self, text: &str) {
            if let Err(error) = self.with_env(|env, activity| {
                let service = env.new_string("clipboard")?;
                let manager = env.call_method(
                    activity,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&service)],
                )?.l()?;
                if manager.as_raw().is_null() {
                    bail!("Android clipboard is unavailable");
                }
                let class = env.find_class(jni_str!("android/content/ClipData"))?;
                let label = env.new_string("EasyVpn")?;
                let text = env.new_string(text)?;
                let clip = env.call_static_method(
                    &class,
                    jni_str!("newPlainText"),
                    jni_sig!("(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;"),
                    &[JValue::Object(&label), JValue::Object(&text)],
                )?.l()?;
                env.call_method(
                    &manager,
                    jni_str!("setPrimaryClip"),
                    jni_sig!("(Landroid/content/ClipData;)V"),
                    &[JValue::Object(&clip)],
                )?;
                Ok(())
            }) {
                log::warn!("Clipboard write failed: {error:#}");
            }
        }

        fn pick_import_file(&self) -> Option<PathBuf> {
            None
        }

        fn open_folder(&self, _path: &Path) {}

        fn start_vpn(&self, socks_port: u16, allowed: &[String], disallowed: &[String]) -> Result<()> {
            if socks_port == 0 {
                bail!("Invalid SOCKS port");
            }
            set_status(VpnStatus::Starting);
            let result = self.with_env(|env, activity| {
                // Use the retained activity's class loader on Rust threads.
                let class = env.get_object_class(activity)?;
                let allowed = env.new_string(allowed.join(","))?;
                let disallowed = env.new_string(disallowed.join(","))?;
                env.call_static_method(
                    &class,
                    jni_str!("startVpn"),
                    jni_sig!("(ILjava/lang/String;Ljava/lang/String;)V"),
                    &[
                        JValue::Int(i32::from(socks_port)),
                        JValue::Object(&allowed),
                        JValue::Object(&disallowed),
                    ],
                )?;
                Ok(())
            });
            if let Err(error) = &result {
                set_status(VpnStatus::Failed(format!("{error:#}")));
            }
            result
        }

        fn stop_vpn(&self) {
            if let Err(error) = self.with_env(|env, activity| {
                let class = env.get_object_class(activity)?;
                env.call_static_method(&class, jni_str!("stopVpn"), jni_sig!("()V"), &[])?;
                Ok(())
            }) {
                log::warn!("Stopping Android VPN failed: {error:#}");
            }
        }

        fn vpn_status(&self) -> VpnStatus {
            lock(status()).clone()
        }

        fn safe_area(&self) -> (f32, f32) {
            self.insets
        }

        fn can_scan_qr(&self) -> bool {
            true
        }

        fn start_qr_scan(&self) -> Result<()> {
            *lock(qr_result()) = None;
            self.with_env(|env, activity| {
                let class = env.get_object_class(activity)?;
                env.call_static_method(&class, jni_str!("startScanner"), jni_sig!("()V"), &[])?;
                Ok(())
            })
        }

        fn take_qr_result(&self) -> Option<std::result::Result<String, String>> {
            lock(qr_result()).take()
        }

        fn set_wake(&self, callback: Arc<dyn Fn() + Send + Sync>) {
            *lock(wake()) = Some(callback);
        }

        fn take_back_press(&self) -> bool {
            BACK_PRESSED.swap(false, Ordering::AcqRel)
        }

        fn move_to_background(&self) {
            if let Err(error) = self.with_env(|env, activity| {
                let class = env.get_object_class(activity)?;
                env.call_static_method(&class, jni_str!("moveToBackground"), jni_sig!("()V"), &[])?;
                Ok(())
            }) {
                log::warn!("Moving the app to the background failed: {error:#}");
            }
        }
    }

    fn read_insets(env: &mut Env<'_>, activity: &JObject<'_>) -> Result<(f32, f32)> {
        let resources = env.call_method(
            activity,
            jni_str!("getResources"),
            jni_sig!("()Landroid/content/res/Resources;"),
            &[],
        )?.l()?;
        let metrics = env.call_method(
            &resources,
            jni_str!("getDisplayMetrics"),
            jni_sig!("()Landroid/util/DisplayMetrics;"),
            &[],
        )?.l()?;
        let density = env.get_field(&metrics, jni_str!("density"), jni_sig!("F"))?.f()?;
        if !density.is_finite() || density <= 0.0 {
            bail!("Invalid Android display density");
        }
        let mut dimension = |name: &str| -> Result<f32> {
            let name = env.new_string(name)?;
            let kind = env.new_string("dimen")?;
            let package = env.new_string("android")?;
            let id = env.call_method(
                &resources,
                jni_str!("getIdentifier"),
                jni_sig!("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I"),
                &[
                    JValue::Object(&name),
                    JValue::Object(&kind),
                    JValue::Object(&package),
                ],
            )?.i()?;
            if id == 0 {
                return Ok(0.0);
            }
            let pixels = env.call_method(
                &resources,
                jni_str!("getDimensionPixelSize"),
                jni_sig!("(I)I"),
                &[JValue::Int(id)],
            )?.i()?;
            Ok(pixels.max(0) as f32 / density)
        };
        Ok((dimension("status_bar_height")?, dimension("navigation_bar_height")?))
    }

    fn configure_paths(platform: &AndroidPlatform) -> Result<()> {
        platform.with_env(|env, activity| {
            let files = env.call_method(
                activity, jni_str!("getFilesDir"), jni_sig!("()Ljava/io/File;"), &[],
            )?.l()?;
            let path = env.call_method(
                &files,
                jni_str!("getAbsolutePath"),
                jni_sig!("()Ljava/lang/String;"),
                &[],
            )?.l()?;
            let home = PathBuf::from(string_object(env, &path)?);
            let info = env.call_method(
                activity,
                jni_str!("getApplicationInfo"),
                jni_sig!("()Landroid/content/pm/ApplicationInfo;"),
                &[],
            )?.l()?;
            let library_dir = env.get_field(
                &info, jni_str!("nativeLibraryDir"), jni_sig!("Ljava/lang/String;"),
            )?.l()?;
            let library_dir = string_object(env, &library_dir)?;
            std::fs::create_dir_all(home.join("assets"))?;
            std::env::set_var("EASYVPN_HOME", &home);
            std::env::set_var("EASYVPN_CORE_DIR", library_dir);
            std::env::set_var("EASYVPN_ASSET_DIR", home.join("assets"));
            Ok(())
        })
    }

    #[unsafe(no_mangle)]
    pub fn android_main(app: AndroidApp) {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("EasyVpn")
                .with_max_level(log::LevelFilter::Info),
        );
        let result = (|| -> Result<()> {
            // SAFETY: AndroidApp's VM and activity are live for this invocation.
            let platform = unsafe { AndroidPlatform::new(&app)? };
            configure_paths(&platform)?;
            let options = eframe::NativeOptions {
                event_loop_builder: Some(Box::new(move |builder| {
                    use winit::platform::android::EventLoopBuilderExtAndroid;
                    builder.with_android_app(app.clone());
                })),
                ..Default::default()
            };
            easyvpn_gui::run_app(options, Box::new(platform))
                .map_err(|error| anyhow!("EasyVpn UI failed: {error}"))
        })();
        if let Err(error) = result {
            log::error!("Android startup failed: {error:#}");
            set_status(VpnStatus::Failed(format!("{error:#}")));
        }
        stop_tun();
    }

    fn start_tun(fd: jint, socks_port: jint, mtu: jint) -> Result<()> {
        if fd < 0 || !(1..=65535).contains(&socks_port) || !(576..=65535).contains(&mtu) {
            bail!("Invalid TUN fd, SOCKS port, or MTU");
        }
        let proxy = ProxyParameters::try_from(format!("socks5://127.0.0.1:{socks_port}").as_str())?;
        let mut args = Args::default();
        args.proxy(proxy)
            .tun_fd(Some(fd))
            .close_fd_on_drop(false)
            .dns(ArgDns::Virtual)
            .dns_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .ipv6_enabled(false)
            .setup(false);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Create TUN runtime")?;
        let mut slot = lock(tun_slot());
        if let Some(previous) = slot.take() {
            previous.cancel.cancel();
            let _ = previous.thread.join();
        }
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let thread = std::thread::Builder::new()
            .name("easyvpn-tun".into())
            .spawn(move || {
                let result: std::io::Result<usize> = runtime.block_on(
                    tun2proxy::general_run_async(args, mtu as u16, false, worker_cancel.clone()),
                );
                if !worker_cancel.is_cancelled() {
                    let message = match result {
                        Ok(_) => "TUN forwarding stopped unexpectedly".to_owned(),
                        Err(error) => format!("TUN forwarding failed: {error}"),
                    };
                    log::error!("{message}");
                    set_status(VpnStatus::Failed(message));
                }
            })
            .context("Spawn TUN worker")?;
        *slot = Some(TunWorker { cancel, thread });
        Ok(())
    }

    /// # Safety
    /// Java supplies a live JNI environment and keeps fd open until stopTun returns.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_com_easyvpn_app_Native_startTun(
        mut env: EnvUnowned<'_>,
        _class: JClass<'_>,
        fd: jint,
        socks_port: jint,
        mtu: jint,
    ) -> jint {
        env.with_env(|_env: &mut Env| -> jni::errors::Result<jint> {
            match start_tun(fd, socks_port, mtu) {
                Ok(()) => Ok(0),
                Err(error) => {
                    let message = format!("{error:#}");
                    log::error!("startTun: {message}");
                    set_status(VpnStatus::Failed(message));
                    Ok(-1)
                }
            }
        }).resolve::<jni::errors::LogErrorAndDefault>()
    }

    /// # Safety
    /// Java must wait for this call before closing its ParcelFileDescriptor.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_com_easyvpn_app_Native_stopTun(
        mut env: EnvUnowned<'_>,
        _class: JClass<'_>,
    ) {
        env.with_env(|_env: &mut Env| -> jni::errors::Result<()> {
            stop_tun();
            Ok(())
        }).resolve::<jni::errors::LogErrorAndDefault>()
    }

    /// # Safety
    /// Java supplies valid local references for this invocation.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_com_easyvpn_app_Native_onVpnState(
        mut env: EnvUnowned<'_>,
        _class: JClass<'_>,
        state: jint,
        message: JString<'_>,
    ) {
        env.with_env(|env: &mut Env| -> jni::errors::Result<()> {
            let message = if message.as_raw().is_null() {
                String::new()
            } else {
                message.try_to_string(env)?
            };
            let value = match state {
                0 => VpnStatus::Idle,
                1 => VpnStatus::Starting,
                2 => {
                    let mut current = lock(status());
                    if !matches!(*current, VpnStatus::Failed(_)) {
                        *current = VpnStatus::Running;
                    }
                    return Ok(());
                }
                3 => VpnStatus::PermissionDenied,
                4 => VpnStatus::Failed(if message.is_empty() {
                    "Android VPN failed".into()
                } else {
                    message
                }),
                other => {
                    log::warn!("Unknown Android VPN state: {other}");
                    return Ok(());
                }
            };
            set_status(value);
            Ok(())
        }).resolve::<jni::errors::LogErrorAndDefault>()
    }

    /// # Safety
    /// Called by Java with a valid JNI environment and byte-array reference.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_com_easyvpn_app_Native_decodeQr(
        mut env: EnvUnowned<'_>,
        _class: JClass<'_>,
        luma: JByteArray<'_>,
        width: jint,
        height: jint,
        row_stride: jint,
    ) -> jstring {
        // Contain decoder and JNI-adapter panics at the native boundary.
        catch_unwind(AssertUnwindSafe(|| {
            env.with_env(|env: &mut Env| -> jni::errors::Result<jstring> {
                if luma.as_raw().is_null()
                    || !(1..=4096).contains(&width)
                    || !(1..=4096).contains(&height)
                    || row_stride < width
                    || row_stride > 65536
                {
                    return Ok(std::ptr::null_mut());
                }
                let bytes = env.convert_byte_array(&luma)?;
                match crate::qr::decode_qr_luma(
                    &bytes,
                    width as usize,
                    height as usize,
                    row_stride as usize,
                ) {
                    Some(text) => Ok(env.new_string(text)?.into_raw()),
                    None => Ok(std::ptr::null_mut()),
                }
            }).resolve::<jni::errors::LogErrorAndDefault>()
        })).unwrap_or(std::ptr::null_mut())
    }

    /// # Safety
    /// Java supplies a valid JNI environment and class.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_com_easyvpn_app_Native_onBack(
        _env: EnvUnowned<'_>,
        _class: JClass<'_>,
    ) {
        BACK_PRESSED.store(true, Ordering::Release);
        // Clone out of the lock so the callback never runs while it is held.
        let callback = lock(wake()).clone();
        if let Some(callback) = callback {
            let _ = catch_unwind(AssertUnwindSafe(|| callback()));
        }
    }

    /// # Safety
    /// Java supplies a valid JNI environment and a String or null.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn Java_com_easyvpn_app_Native_onQrResult(
        mut env: EnvUnowned<'_>,
        _class: JClass<'_>,
        state: jint,
        text: JString<'_>,
    ) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            env.with_env(|env: &mut Env| -> jni::errors::Result<()> {
                let text = if text.as_raw().is_null() {
                    String::new()
                } else {
                    text.try_to_string(env)?
                };
                let result = match state {
                    0 => Ok(text),
                    1 => Err("cancelled".to_owned()),
                    _ => Err(if text.is_empty() {
                        "QR scanning failed".to_owned()
                    } else {
                        text
                    }),
                };
                *lock(qr_result()) = Some(result);
                Ok(())
            }).resolve::<jni::errors::LogErrorAndDefault>()
        }));
    }
}
