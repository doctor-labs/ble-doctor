use clap::Parser;

#[tokio::main]
async fn main() -> ble_doctor::error::Result<()> {
    ble_doctor::cli::run(ble_doctor::cli::Cli::parse());
    Ok(())
}
