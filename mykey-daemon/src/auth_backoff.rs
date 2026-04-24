pub fn password_backoff_secs(failed_attempts: u32) -> u64 {
    match failed_attempts {
        0..=1 => 0,
        2 => 5,
        3 => 15,
        4 => 30,
        5 => 60,
        6 => 120,
        7 => 300,
        _ => 600,
    }
}
