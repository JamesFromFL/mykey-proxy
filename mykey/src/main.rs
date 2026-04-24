use std::env;
use std::process::{Command, ExitCode};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Topic {
    name: &'static str,
    summary: &'static str,
    usage: &'static [&'static str],
    examples: &'static [&'static str],
    notes: &'static [&'static str],
}

enum Action<'a> {
    PrintGeneralHelp,
    PrintTopicHelp(&'a Topic),
    PrintVersion,
    Run {
        binary: &'static str,
        args: Vec<String>,
    },
    Error(String),
}

const TOPICS: &[Topic] = &[
    Topic {
        name: "auth",
        summary: "Run MyKey auth setup, manage PAM integration, and inspect local-auth status.",
        usage: &[
            "mykey auth setup",
            "mykey auth enable",
            "mykey auth disable",
            "mykey auth login",
            "mykey auth logout",
            "mykey auth status",
            "mykey auth biometrics",
        ],
        examples: &[
            "sudo mykey auth setup",
            "sudo mykey auth enable",
            "sudo mykey auth login",
            "mykey auth status",
            "sudo mykey auth biometrics",
        ],
        notes: &[
            "The short aliases `mykey enable`, `mykey disable`, `mykey login`, `mykey logout`, `mykey status`, and `mykey biometrics` route here.",
            "Use `sudo` for commands that modify PAM or enrollment state.",
        ],
    },
    Topic {
        name: "pin",
        summary: "Manage the MyKey PIN and inspect PIN state.",
        usage: &[
            "mykey pin set",
            "mykey pin reset",
            "mykey pin status",
        ],
        examples: &[
            "mykey pin set",
            "mykey pin reset",
            "mykey pin status",
        ],
        notes: &[
            "The MyKey PIN is the fallback backend for local auth when biometrics or security keys are enabled.",
        ],
    },
    Topic {
        name: "security-key",
        summary: "Enroll, inspect, test, and remove security keys.",
        usage: &[
            "mykey security-key enroll [--nickname <name>]",
            "mykey security-key status",
            "mykey security-key test",
            "mykey security-key unenroll",
        ],
        examples: &[
            "sudo mykey security-key enroll --nickname \"Desk Key\"",
            "mykey security-key status",
            "mykey security-key test",
        ],
        notes: &[
            "Use `sudo` for enroll and unenroll because MyKey treats them as elevated management actions.",
        ],
    },
    Topic {
        name: "tray",
        summary: "Manage the optional MyKey tray service.",
        usage: &[
            "mykey tray enable",
            "mykey tray disable",
            "mykey tray status",
        ],
        examples: &[
            "mykey tray status",
            "mykey tray enable",
        ],
        notes: &[
            "The tray is optional and separate from the core auth surface.",
        ],
    },
    Topic {
        name: "secrets",
        summary: "Run or inspect the Secret Service provider component.",
        usage: &["mykey secrets [component args]"],
        examples: &["mykey secrets"],
        notes: &[
            "This forwards directly to `mykey-secrets`.",
        ],
    },
    Topic {
        name: "migrate",
        summary: "Enroll or unenroll MyKey as the Secret Service provider and migrate secrets.",
        usage: &[
            "mykey migrate --enroll",
            "mykey migrate --unenroll",
        ],
        examples: &[
            "mykey migrate --enroll",
            "mykey migrate --unenroll",
        ],
        notes: &[
            "This forwards directly to `mykey-migrate`.",
        ],
    },
    Topic {
        name: "daemon",
        summary: "Run the MyKey daemon binary directly.",
        usage: &["mykey daemon [daemon args]"],
        examples: &["mykey daemon"],
        notes: &[
            "This is primarily useful for development and debugging, not normal operator workflows.",
        ],
    },
    Topic {
        name: "manager",
        summary: "Launch the placeholder GUI manager binary.",
        usage: &["mykey manager"],
        examples: &["mykey manager"],
        notes: &[
            "The GUI manager is still deferred. The `mykey` terminal control surface is the primary entrypoint for now.",
        ],
    },
];

fn main() -> ExitCode {
    match determine_action(env::args().skip(1).collect()) {
        Action::PrintGeneralHelp => {
            print_general_help();
            ExitCode::SUCCESS
        }
        Action::PrintTopicHelp(topic) => {
            print_topic_help(topic);
            ExitCode::SUCCESS
        }
        Action::PrintVersion => {
            println!("mykey {VERSION}");
            ExitCode::SUCCESS
        }
        Action::Run { binary, args } => run_binary(binary, &args),
        Action::Error(message) => {
            eprintln!("{message}");
            eprintln!();
            print_general_help();
            ExitCode::from(2)
        }
    }
}

fn determine_action(args: Vec<String>) -> Action<'static> {
    let Some(command) = args.first().map(String::as_str) else {
        return Action::PrintGeneralHelp;
    };

    match command {
        "-h" | "--help" => Action::PrintGeneralHelp,
        "-V" | "--version" | "version" => Action::PrintVersion,
        "help" => match args.get(1) {
            Some(topic) => match find_topic(topic) {
                Some(topic) => Action::PrintTopicHelp(topic),
                None => Action::Error(format!("Unknown MyKey help topic: {topic}")),
            },
            None => Action::PrintGeneralHelp,
        },
        "auth" => Action::Run {
            binary: "mykey-auth",
            args: args[1..].to_vec(),
        },
        "enable" | "disable" | "login" | "logout" | "status" | "biometrics" => Action::Run {
            binary: "mykey-auth",
            args,
        },
        "pin" => Action::Run {
            binary: "mykey-pin",
            args: args[1..].to_vec(),
        },
        "security-key" => Action::Run {
            binary: "mykey-security-key",
            args: args[1..].to_vec(),
        },
        "tray" => Action::Run {
            binary: "mykey-tray",
            args: args[1..].to_vec(),
        },
        "secrets" => Action::Run {
            binary: "mykey-secrets",
            args: args[1..].to_vec(),
        },
        "migrate" => Action::Run {
            binary: "mykey-migrate",
            args: args[1..].to_vec(),
        },
        "daemon" => Action::Run {
            binary: "mykey-daemon",
            args: args[1..].to_vec(),
        },
        "manager" => Action::Run {
            binary: "mykey-manager",
            args: args[1..].to_vec(),
        },
        other => Action::Error(format!("Unknown MyKey command: {other}")),
    }
}

fn find_topic(name: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|topic| topic.name == name)
}

fn print_general_help() {
    println!("MyKey terminal control surface");
    println!();
    println!("Usage:");
    println!("  mykey <command> [args]");
    println!("  mykey help <topic>");
    println!();
    println!("Primary workflows:");
    println!("  mykey status                Show local-auth and PAM integration status");
    println!("  sudo mykey enable           Enable MyKey on supported base PAM targets");
    println!("  sudo mykey login            Opt into MyKey-managed login and unlock targets");
    println!("  mykey pin set               Create the MyKey PIN fallback");
    println!("  sudo mykey biometrics       Enroll or manage biometric providers");
    println!("  sudo mykey security-key enroll [--nickname <name>]");
    println!();
    println!("Command groups:");
    for topic in TOPICS {
        println!("  {:<14} {}", topic.name, topic.summary);
    }
    println!();
    println!("Routing aliases:");
    println!("  enable, disable, login, logout, status, biometrics");
    println!("  These route to `mykey auth ...` for faster day-to-day use.");
    println!();
    println!("Examples:");
    println!("  mykey help auth");
    println!("  mykey auth status");
    println!("  mykey pin status");
    println!("  mykey security-key test");
}

fn print_topic_help(topic: &Topic) {
    println!("mykey {}", topic.name);
    println!();
    println!("{}", topic.summary);
    println!();
    println!("Usage:");
    for usage in topic.usage {
        println!("  {usage}");
    }
    println!();
    println!("Examples:");
    for example in topic.examples {
        println!("  {example}");
    }
    if !topic.notes.is_empty() {
        println!();
        println!("Notes:");
        for note in topic.notes {
            println!("  {note}");
        }
    }
}

fn run_binary(binary: &str, args: &[String]) -> ExitCode {
    let status = match Command::new(binary).args(args).status() {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "Could not find `{binary}` on PATH. Install the matching MyKey component first."
            );
            return ExitCode::from(127);
        }
        Err(error) => {
            eprintln!("Could not launch `{binary}`: {error}");
            return ExitCode::from(1);
        }
    };

    match status.code() {
        Some(code) => ExitCode::from(code as u8),
        None => {
            eprintln!("`{binary}` terminated without an exit status.");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{determine_action, find_topic, Action};

    #[test]
    fn no_args_prints_general_help() {
        assert!(matches!(determine_action(Vec::new()), Action::PrintGeneralHelp));
    }

    #[test]
    fn auth_alias_routes_to_mykey_auth() {
        match determine_action(vec!["status".to_string()]) {
            Action::Run { binary, args } => {
                assert_eq!(binary, "mykey-auth");
                assert_eq!(args, vec!["status".to_string()]);
            }
            _ => panic!("expected routed auth action"),
        }
    }

    #[test]
    fn module_routes_strip_the_module_name() {
        match determine_action(vec!["pin".to_string(), "status".to_string()]) {
            Action::Run { binary, args } => {
                assert_eq!(binary, "mykey-pin");
                assert_eq!(args, vec!["status".to_string()]);
            }
            _ => panic!("expected routed pin action"),
        }
    }

    #[test]
    fn help_topic_is_resolved() {
        match determine_action(vec!["help".to_string(), "auth".to_string()]) {
            Action::PrintTopicHelp(topic) => assert_eq!(topic.name, "auth"),
            _ => panic!("expected topic help action"),
        }
    }

    #[test]
    fn unknown_command_is_rejected() {
        match determine_action(vec!["unknown".to_string()]) {
            Action::Error(message) => assert!(message.contains("Unknown MyKey command")),
            _ => panic!("expected error action"),
        }
    }

    #[test]
    fn topics_cover_security_key_surface() {
        let topic = find_topic("security-key").expect("security-key topic");
        assert!(topic.summary.contains("security"));
        assert!(topic.usage.iter().any(|line| line.contains("enroll")));
    }
}
