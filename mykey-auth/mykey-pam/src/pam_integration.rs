use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const MYKEY_PAM_LINE: &str =
    "-auth    [success=done ignore=ignore authinfo_unavail=ignore default=bad]    pam_mykey.so";

const MANAGED_BLOCK_START: &str = "# BEGIN MYKEY MANAGED AUTH";
const MANAGED_BLOCK_END: &str = "# END MYKEY MANAGED AUTH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PamTarget {
    pub name: &'static str,
    pub service: &'static str,
    pub description: &'static str,
}

impl PamTarget {
    pub fn etc_path(self) -> PathBuf {
        PathBuf::from("/etc/pam.d").join(self.service)
    }

    pub fn vendor_path(self) -> PathBuf {
        PathBuf::from("/usr/lib/pam.d").join(self.service)
    }

    pub fn config_path(self) -> String {
        self.etc_path().display().to_string()
    }
}

pub const BASE_TARGETS: &[PamTarget] = &[
    PamTarget {
        name: "sudo",
        service: "sudo",
        description: "sudo elevation",
    },
    PamTarget {
        name: "polkit-1",
        service: "polkit-1",
        description: "polkit elevation dialogs",
    },
];

pub const LOGIN_TARGETS: &[PamTarget] = &[
    PamTarget {
        name: "login",
        service: "login",
        description: "TTY login and PAM stacks that include login",
    },
    PamTarget {
        name: "greetd",
        service: "greetd",
        description: "greetd login manager",
    },
    PamTarget {
        name: "gdm-password",
        service: "gdm-password",
        description: "GNOME login manager",
    },
    PamTarget {
        name: "gdm-fingerprint",
        service: "gdm-fingerprint",
        description: "GNOME fingerprint login path",
    },
    PamTarget {
        name: "sddm",
        service: "sddm",
        description: "SDDM login manager",
    },
    PamTarget {
        name: "lightdm",
        service: "lightdm",
        description: "LightDM login manager",
    },
    PamTarget {
        name: "kde",
        service: "kde",
        description: "Plasma screen lock",
    },
    PamTarget {
        name: "kde-fingerprint",
        service: "kde-fingerprint",
        description: "Plasma fingerprint unlock",
    },
    PamTarget {
        name: "cinnamon-screensaver",
        service: "cinnamon-screensaver",
        description: "Cinnamon screen lock",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamTargetState {
    Enabled,
    Disabled,
    Manual,
    BrokenManagedBlock,
    Absent,
}

impl PamTargetState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Manual => "manual",
            Self::BrokenManagedBlock => "broken",
            Self::Absent => "absent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PamTargetSource {
    Etc,
    Vendor,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PamTargetInspection {
    pub target: PamTarget,
    pub state: PamTargetState,
    source: PamTargetSource,
}

impl PamTargetInspection {
    pub fn display_path(self) -> String {
        match self.source {
            PamTargetSource::Etc | PamTargetSource::None => self.target.config_path(),
            PamTargetSource::Vendor => format!(
                "{} (vendor: {})",
                self.target.etc_path().display(),
                self.target.vendor_path().display()
            ),
        }
    }

    pub fn is_present(self) -> bool {
        !matches!(self.state, PamTargetState::Absent)
    }
}

pub fn inspect_targets(targets: &[PamTarget]) -> Result<Vec<PamTargetInspection>, String> {
    targets.iter().copied().map(inspect_target).collect()
}

pub fn enable_targets(targets: &[PamTarget]) -> Result<Vec<String>, String> {
    let mut changed = Vec::new();
    for target in targets {
        let inspection = inspect_target(*target)?;
        match inspection.state {
            PamTargetState::Enabled => {}
            PamTargetState::Absent => {}
            PamTargetState::Disabled => {
                enable_target(*target)?;
                changed.push(target.name.to_string());
            }
            PamTargetState::Manual => {
                return Err(format!(
                    "{} already contains a pam_mykey entry outside the MyKey-managed block. \
Remove or normalise it before rerunning mykey-auth.",
                    inspection.display_path()
                ));
            }
            PamTargetState::BrokenManagedBlock => {
                return Err(format!(
                    "{} has a broken MyKey-managed PAM block. Fix it manually before rerunning mykey-auth.",
                    inspection.display_path()
                ));
            }
        }
    }
    Ok(changed)
}

pub fn disable_targets(targets: &[PamTarget]) -> Result<Vec<String>, String> {
    let mut changed = Vec::new();
    for target in targets {
        let inspection = inspect_target(*target)?;
        match inspection.state {
            PamTargetState::Enabled => {
                disable_target(*target)?;
                changed.push(target.name.to_string());
            }
            PamTargetState::Disabled | PamTargetState::Absent => {}
            PamTargetState::Manual => {
                return Err(format!(
                    "{} contains a pam_mykey entry outside the MyKey-managed block. \
Refusing to modify it automatically.",
                    inspection.display_path()
                ));
            }
            PamTargetState::BrokenManagedBlock => {
                return Err(format!(
                    "{} has a broken MyKey-managed PAM block. Fix it manually before rerunning mykey-auth.",
                    inspection.display_path()
                ));
            }
        }
    }
    Ok(changed)
}

fn inspect_target(target: PamTarget) -> Result<PamTargetInspection, String> {
    let etc_path = target.etc_path();
    if etc_path.exists() {
        let text = read_text(&etc_path)?;
        return Ok(PamTargetInspection {
            target,
            state: inspect_text(&text),
            source: PamTargetSource::Etc,
        });
    }

    let vendor_path = target.vendor_path();
    if vendor_path.exists() {
        let text = read_text(&vendor_path)?;
        let state = match inspect_text(&text) {
            PamTargetState::Enabled | PamTargetState::Manual => PamTargetState::Manual,
            other => other,
        };
        return Ok(PamTargetInspection {
            target,
            state,
            source: PamTargetSource::Vendor,
        });
    }

    Ok(PamTargetInspection {
        target,
        state: PamTargetState::Absent,
        source: PamTargetSource::None,
    })
}

fn inspect_text(text: &str) -> PamTargetState {
    let start_count = text.matches(MANAGED_BLOCK_START).count();
    let end_count = text.matches(MANAGED_BLOCK_END).count();
    if start_count != end_count || start_count > 1 {
        return PamTargetState::BrokenManagedBlock;
    }
    if start_count == 1 {
        if text.contains(MYKEY_PAM_LINE) {
            return PamTargetState::Enabled;
        }
        return PamTargetState::BrokenManagedBlock;
    }
    if text.contains("pam_mykey.so") {
        return PamTargetState::Manual;
    }
    PamTargetState::Disabled
}

fn enable_target(target: PamTarget) -> Result<(), String> {
    let etc_path = target.etc_path();
    let source_path = if etc_path.exists() {
        etc_path.clone()
    } else {
        let vendor_path = target.vendor_path();
        if vendor_path.exists() {
            vendor_path
        } else {
            return Err(format!(
                "No PAM file found for {} ({})",
                target.name, target.description
            ));
        }
    };

    let text = read_text(&source_path)?;
    let mut lines: Vec<String> = text.lines().map(ToString::to_string).collect();
    let block = managed_block_lines();
    let insert_at = insertion_index(&lines);
    lines.splice(insert_at..insert_at, block);
    write_lines_atomic(&etc_path, &lines)
}

fn disable_target(target: PamTarget) -> Result<(), String> {
    let etc_path = target.etc_path();
    if !etc_path.exists() {
        return Err(format!(
            "Cannot remove the MyKey-managed PAM block from {} because no override exists.",
            etc_path.display()
        ));
    }

    let text = read_text(&etc_path)?;
    let lines: Vec<String> = text.lines().map(ToString::to_string).collect();
    let (start, end) = managed_block_range(&lines).ok_or_else(|| {
        format!(
            "Cannot find MyKey-managed PAM block in {}",
            etc_path.display()
        )
    })?;
    let mut new_lines = lines;
    new_lines.drain(start..=end);
    while new_lines
        .get(start)
        .is_some_and(|line| line.trim().is_empty())
        && new_lines
            .get(start.wrapping_sub(1))
            .is_some_and(|line| line.trim().is_empty())
    {
        new_lines.remove(start);
    }

    let new_content = render_lines(&new_lines);
    let vendor_path = target.vendor_path();
    if vendor_path.exists() {
        let vendor_content = read_text(&vendor_path)?;
        if normalised(&new_content) == normalised(&vendor_content) {
            std::fs::remove_file(&etc_path)
                .map_err(|e| format!("Cannot remove {}: {e}", etc_path.display()))?;
            return Ok(());
        }
    }

    write_lines_atomic(&etc_path, &new_lines)
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))
}

fn insertion_index(lines: &[String]) -> usize {
    lines
        .iter()
        .position(|line| !is_prologue_line(line))
        .unwrap_or(lines.len())
}

fn is_prologue_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || trimmed == "%PAM-1.0"
        || trimmed == "#%PAM-1.0"
        || trimmed.starts_with('#')
}

fn managed_block_lines() -> Vec<String> {
    vec![
        MANAGED_BLOCK_START.to_string(),
        MYKEY_PAM_LINE.to_string(),
        MANAGED_BLOCK_END.to_string(),
        String::new(),
    ]
}

fn managed_block_range(lines: &[String]) -> Option<(usize, usize)> {
    let start = lines
        .iter()
        .position(|line| line.trim() == MANAGED_BLOCK_START)?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim() == MANAGED_BLOCK_END)
        .map(|idx| start + 1 + idx)?;
    Some((start, end))
}

fn render_lines(lines: &[String]) -> String {
    let mut content = lines.join("\n");
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content
}

fn normalised(text: &str) -> String {
    text.replace("\r\n", "\n")
        .trim_end_matches('\n')
        .to_string()
}

fn write_lines_atomic(path: &Path, lines: &[String]) -> Result<(), String> {
    let content = render_lines(lines);

    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    }
    let mode = file_mode(path).unwrap_or(0o644);
    let temp_path = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("pam"),
        std::process::id()
    ));

    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(&temp_path)
        .map_err(|e| format!("Cannot open {}: {e}", temp_path.display()))?;

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp_path)
        .map_err(|e| format!("Cannot open {}: {e}", temp_path.display()))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("Cannot write {}: {e}", temp_path.display()))?;
    file.sync_all()
        .map_err(|e| format!("Cannot sync {}: {e}", temp_path.display()))?;

    std::fs::rename(&temp_path, path).map_err(|e| format!("Cannot replace {}: {e}", path.display()))
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode())
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_happens_after_header_comments() {
        let lines = vec![
            "#%PAM-1.0".to_string(),
            "# comment".to_string(),
            String::new(),
            "auth sufficient pam_fprintd.so".to_string(),
            "auth include system-auth".to_string(),
        ];

        assert_eq!(insertion_index(&lines), 3);
    }

    #[test]
    fn managed_block_range_detects_inserted_block() {
        let mut lines = vec!["#%PAM-1.0".to_string()];
        lines.extend(managed_block_lines());
        lines.push("auth include system-auth".to_string());

        assert_eq!(managed_block_range(&lines), Some((1, 3)));
    }

    #[test]
    fn inspect_manual_when_unmanaged_pam_mykey_exists() {
        assert_eq!(
            inspect_text("auth sufficient pam_mykey.so\n"),
            PamTargetState::Manual
        );
    }

    #[test]
    fn normalised_ignores_trailing_newlines() {
        assert_eq!(normalised("a\n"), normalised("a\n\n"));
    }
}
