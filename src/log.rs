/// Debug logging, compiled out unless the `debug-logging` feature is enabled.
///
/// The handshake path used to print the client's login and dump whole TLS
/// records to stderr unconditionally. On a server that turns stderr into a
/// record of who connected and when, plus their traffic — exactly what a seized
/// machine should not be holding. Gating it behind a feature means a release
/// build emits nothing at all, rather than relying on the operator to redirect
/// stderr.
///
/// Use this for anything on the connection path. Never log a login, a
/// credential, a key, a nonce, or record contents even behind the feature.
#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logging")]
        {
            eprintln!($($arg)*);
        }
    };
}