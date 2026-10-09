#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        if heptabao_plugin_host::sealed_exec_adapter::run().is_ok() {
            return std::process::ExitCode::SUCCESS;
        }
    }
    // Fixed text only: no request, response, identity, path or operator values.
    eprintln!("sealed executable handoff refused");
    std::process::ExitCode::from(2)
}
