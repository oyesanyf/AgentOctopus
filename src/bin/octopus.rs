use agent_octopus::cli::{
    dispatch_operational_subcommand, parse_octopus_cli, print_octopus_help, print_octopus_run_help,
    run::execute_octopus_run, CliParseResult, EXIT_PREFLIGHT_DENIED,
};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli_args: Vec<String> = std::env::args().collect();

    // One-shot elevated UAC helper delegation for Windows WFP & WUA COM kernel patching.
    for i in 1..cli_args.len() {
        if cli_args[i] == "--wfp-kernel-apply" {
            let action = cli_args.get(i + 1).map(|s| s.as_str()).unwrap_or("");
            match agent_octopus::security::handle_wfp_kernel_apply_cli(action) {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("[WFP-HELPER-ERROR] {e}");
                    std::process::exit(1);
                }
            }
        }
        if cli_args[i] == "--kernel-patch-apply" {
            let auto_accept = cli_args.iter().any(|a| a == "--accept-eula");
            match agent_octopus::security::kernel_patcher::handle_kernel_patch_apply_cli(
                auto_accept,
            )
            .await
            {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("[KERNEL-PATCH-HELPER-ERROR] {e}");
                    std::process::exit(1);
                }
            }
        }
    }

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
