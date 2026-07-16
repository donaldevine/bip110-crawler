//! Minimal UTC timestamps, shared by the crawler (stamping when a peer was last
//! confirmed reachable), the DB writer, and the API's freshness cutoff.
//!
//! Format is fixed-width `YYYY-MM-DDTHH:MM:SSZ`, so plain string comparison is also a
//! chronological comparison — which is what lets the API age out stale rows with a simple
//! `last_seen >= cutoff` in SQL. No date crate needed.

/// Format a Unix timestamp (seconds) as `YYYY-MM-DDTHH:MM:SSZ`.
fn iso_from_unix(secs: u64) -> String {
    // Days since epoch -> civil date (Howard Hinnant's algorithm).
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_iso() -> String {
    iso_from_unix(unix_now())
}

/// UTC timestamp `secs` in the past — used as the "still fresh" cutoff for reads.
pub fn iso_secs_ago(secs: u64) -> String {
    iso_from_unix(unix_now().saturating_sub(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_is_fixed_width_and_orders_chronologically() {
        // A known epoch second: 2021-01-01T00:00:00Z.
        assert_eq!(iso_from_unix(1_609_459_200), "2021-01-01T00:00:00Z");
        // Lexicographic order == chronological order (what the SQL cutoff relies on).
        assert!(iso_from_unix(1_609_459_200) < iso_from_unix(1_609_459_201));
        assert!(iso_from_unix(1_000_000_000) < iso_from_unix(2_000_000_000));
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn cutoff_is_in_the_past() {
        assert!(iso_secs_ago(3600) < now_iso());
    }
}
