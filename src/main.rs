#[tokio::main]
async fn main() -> std::process::ExitCode {
    ble_doctor::cli::run()
}
