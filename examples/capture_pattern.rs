use bsobfs::obfs_data::pattern_store::PatternStore;
use bsobfs::wreq::IntoEmulation;
use bsobfs::wreq_util::Emulation;

#[tokio::main]
async fn main() {
    let cover_host = std::env::var("COVER_HOST").unwrap_or_else(|_| "www.pinterest.com".into());

    let store = PatternStore::new("cli_pattern.bin", "serv_pattern.bin");
    let patterns = store
        .load_or_capture(
            Emulation::Firefox151.into_emulation(),
            format!("{cover_host}:443"),
            format!("https://{cover_host}/"),
        )
        .await;

    for (name, pattern) in [("client -> server", &patterns.client), ("server -> client", &patterns.server)] {
        println!(
            "{name}: {} records, {} bytes, {} distinct sizes",
            pattern.order_overall_len(),
            pattern.bandwidth_overall_len(),
            pattern.known_packet_sizes().len()
        );
        let mut sizes: Vec<_> = pattern.known_packet_sizes().iter().collect();
        sizes.sort_unstable();
        for (size, count) in sizes {
            println!("  {size:>6} bytes x {count}");
        }
    }
}
