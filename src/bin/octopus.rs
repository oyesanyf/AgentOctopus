use agent_octopus::cli::{
    dispatch_operational_subcommand, parse_octopus_cli, print_octopus_help, print_octopus_run_help,
    run::execute_octopus_run, CliParseResult, EXIT_PREFLIGHT_DENIED,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli_args: Vec<String> = std::env::args().collect();
    match parse_octopus_cli(&cli_args) {
        CliParseResult::Help => {
            print_octopus_help();
            std::process::exit(0);
        }
        CliParseResult::RunHelp => {
            print_octopus_run_help();
            std::process::exit(0);
        }
        CliParseResult::Version => {
            println!("octopus {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        CliParseResult::Invalid(msg) => {
            eprintln!("[octopus] error: {}\nRun 'octopus --help' for usage.", msg);
            std::process::exit(EXIT_PREFLIGHT_DENIED);
        }
        CliParseResult::Run(run_args) => {
            let code = execute_octopus_run(run_args).await;
            std::process::exit(code);
        }
        CliParseResult::Delegate(sub) => {
            let code = match dispatch_operational_subcommand(&cli_args).await {
                Some(c) => c,
                None => {
                    eprintln!(
                        "[octopus] error: subcommand '{}' is not implemented.\nRun 'octopus --help' for usage.",
                        sub
                    );
                    EXIT_PREFLIGHT_DENIED
                }
            };
            std::process::exit(code);
        }
    }
}
