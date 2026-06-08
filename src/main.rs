fn main() {
    if let Err(error) = scopeguard::cli::run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
