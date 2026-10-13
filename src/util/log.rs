#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logging")]
        {
            eprintln!($($arg)*);
        }
    };
}