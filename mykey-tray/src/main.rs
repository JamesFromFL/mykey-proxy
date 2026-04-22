mod status;
mod tray;

use std::time::Duration;

use log::{error, info};

use crate::status::StatusSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Run,
    Enable,
    Disable,
    Status,
}

fn setup_logger() {
    let Some(log_path) = std::env::var_os("MYKEY_TRAY_LOG") else {
        return;
    };

    let Ok(log_file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    else {
        return;
    };

    let mut builder = env_logger::Builder::new();
    builder
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_secs();
    let _ = builder.try_init();
}

fn parse_command() -> Result<Command, String> {
    let mut args = std::env::args().skip(1);
    let Some(arg) = args.next() else {
        return Ok(Command::Run);
    };

    if args.next().is_some() {
        return Err("Too many arguments.".into());
    }

    match arg.as_str() {
        "run" => Ok(Command::Run),
        "enable" => Ok(Command::Enable),
        "disable" => Ok(Command::Disable),
        "status" => Ok(Command::Status),
        other => Err(format!("Unknown command: {other}")),
    }
}

fn print_usage() {
    eprintln!("Usage: mykey-tray [run|enable|disable|status]");
}

fn print_status(snapshot: &StatusSnapshot) {
    for line in snapshot.lines() {
        println!("{line}");
    }
}

fn run_tray() -> Result<(), String> {
    let initial = StatusSnapshot::gather();
    if !initial.daemon_is_active() {
        info!("mykey-daemon is not active; skipping tray startup");
        return Ok(());
    }

    let service = ksni::TrayService::new(tray::MyKeyTray::new(initial.clone()));
    let handle = service.handle();

    std::thread::spawn(move || {
        let mut last_snapshot = initial;
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let next_snapshot = StatusSnapshot::gather();
            if next_snapshot != last_snapshot {
                let snapshot_for_tray = next_snapshot.clone();
                handle.update(|tray| tray.set_snapshot(snapshot_for_tray));
                last_snapshot = next_snapshot;
            }
            if !last_snapshot.daemon_is_active() {
                info!("mykey-daemon is no longer active; shutting down tray");
                handle.shutdown();
                break;
            }
        }
    });

    service
        .run()
        .map_err(|e| format!("mykey-tray failed to start: {e}"))
}

fn main() {
    let command = parse_command().unwrap_or_else(|msg| {
        eprintln!("{msg}");
        print_usage();
        std::process::exit(2);
    });

    match command {
        Command::Enable => {
            if let Err(e) = status::enable_tray() {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Command::Disable => {
            if let Err(e) = status::disable_tray() {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Command::Status => {
            print_status(&StatusSnapshot::gather());
        }
        Command::Run => {
            setup_logger();
            info!(
                "mykey-tray started (pid={}, version={})",
                std::process::id(),
                env!("CARGO_PKG_VERSION")
            );

            if let Err(e) = run_tray() {
                error!("{e}");
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}
