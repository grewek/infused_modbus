// `fuse-permissions.toml`: technician-configurable `mode`/`uid`/`gid` per
// top-level FUSE directory — a third config category alongside
// device-description TOML (data shape) and connection CLI/config (how to
// connect), this one governing local filesystem exposure policy (see
// CLAUDE.md's "Planned: TLS transport security & client trust"). Every
// field is optional; an absent directory section, or an absent file
// entirely, keeps that directory's previous hardcoded behavior (mode
// 0o755, owned by the process's own real UID/GID — see
// `InfusedFilesystem::directory_attr`).
//
// `client-trust/` is deliberately not configurable here at all: it must
// stay hardcoded to `0o700`/the server's own real UID/GID regardless of
// what a technician writes (T3), so an attempt to configure it — like any
// other unrecognized key, via `deny_unknown_fields` — is a hard parse
// error, not a silently-ignored setting.

use serde::Deserialize;
use std::fmt;

/// Matches the mode every directory in this filesystem has used until now
/// (see `InfusedFilesystem::directory_attr`) — an unconfigured directory
/// keeps behaving exactly as before.
const DEFAULT_MODE: u16 = 0o755;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirectoryPermissions {
    mode: Option<u16>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFusePermissions {
    #[serde(rename = "holding-registers", default)]
    holding_registers: RawDirectoryPermissions,
    #[serde(default)]
    transactions: RawDirectoryPermissions,
    #[serde(default)]
    report: RawDirectoryPermissions,
    #[serde(default)]
    coils: RawDirectoryPermissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryPermissions {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

impl DirectoryPermissions {
    fn from_raw(raw: RawDirectoryPermissions, real_uid: u32, real_gid: u32) -> Self {
        DirectoryPermissions {
            mode: raw.mode.unwrap_or(DEFAULT_MODE),
            uid: raw.uid.unwrap_or(real_uid),
            gid: raw.gid.unwrap_or(real_gid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FusePermissions {
    pub holding_registers: DirectoryPermissions,
    pub transactions: DirectoryPermissions,
    pub report: DirectoryPermissions,
    pub coils: DirectoryPermissions,
}

#[derive(Debug)]
pub struct FusePermissionsError(toml::de::Error);

impl fmt::Display for FusePermissionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for FusePermissionsError {}

impl From<toml::de::Error> for FusePermissionsError {
    fn from(error: toml::de::Error) -> Self {
        FusePermissionsError(error)
    }
}

/// The process's own real UID/GID (not the effective or FUSE-caller one) —
/// the default owner for any directory a technician doesn't explicitly
/// configure, matching the "owned by the server's own service account"
/// discipline used elsewhere (TLS private key, admin socket).
fn real_uid_and_gid() -> (u32, u32) {
    // SAFETY: getuid()/getgid() take no arguments, perform no memory
    // access, and cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

impl FusePermissions {
    pub fn parse(toml_source: &str) -> Result<Self, FusePermissionsError> {
        let raw: RawFusePermissions = toml::from_str(toml_source)?;
        let (real_uid, real_gid) = real_uid_and_gid();
        Ok(FusePermissions {
            holding_registers: DirectoryPermissions::from_raw(
                raw.holding_registers,
                real_uid,
                real_gid,
            ),
            transactions: DirectoryPermissions::from_raw(raw.transactions, real_uid, real_gid),
            report: DirectoryPermissions::from_raw(raw.report, real_uid, real_gid),
            coils: DirectoryPermissions::from_raw(raw.coils, real_uid, real_gid),
        })
    }
}

impl Default for FusePermissions {
    /// Same result as parsing an empty file — every directory keeps its
    /// previous hardcoded behavior. Used when no `fuse-permissions.toml`
    /// was given at all.
    fn default() -> Self {
        FusePermissions::parse("").expect("an empty TOML source always parses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_of_empty_source_uses_defaults_for_every_directory() {
        let (real_uid, real_gid) = real_uid_and_gid();
        let expected = DirectoryPermissions {
            mode: DEFAULT_MODE,
            uid: real_uid,
            gid: real_gid,
        };

        let permissions = FusePermissions::parse("").unwrap();

        assert_eq!(permissions.holding_registers, expected);
        assert_eq!(permissions.transactions, expected);
        assert_eq!(permissions.report, expected);
        assert_eq!(permissions.coils, expected);
    }

    #[test]
    fn default_matches_parsing_an_empty_source() {
        assert_eq!(
            FusePermissions::default(),
            FusePermissions::parse("").unwrap()
        );
    }

    #[test]
    fn parse_reads_a_fully_specified_directory() {
        let toml_source = r#"
            [transactions]
            mode = 0o600
            uid = 1000
            gid = 1000
        "#;

        let permissions = FusePermissions::parse(toml_source).unwrap();

        assert_eq!(
            permissions.transactions,
            DirectoryPermissions {
                mode: 0o600,
                uid: 1000,
                gid: 1000,
            }
        );
    }

    #[test]
    fn parse_supports_a_partial_override() {
        let toml_source = r#"
            [report]
            mode = 0o444
        "#;
        let (real_uid, real_gid) = real_uid_and_gid();

        let permissions = FusePermissions::parse(toml_source).unwrap();

        assert_eq!(
            permissions.report,
            DirectoryPermissions {
                mode: 0o444,
                uid: real_uid,
                gid: real_gid,
            }
        );
    }

    #[test]
    fn parse_reads_the_holding_registers_dashed_key() {
        let toml_source = r#"
            [holding-registers]
            mode = 0o750
        "#;

        let permissions = FusePermissions::parse(toml_source).unwrap();

        assert_eq!(permissions.holding_registers.mode, 0o750);
    }

    #[test]
    fn parse_leaves_unconfigured_directories_at_their_default() {
        let toml_source = r#"
            [coils]
            mode = 0o700
        "#;
        let (real_uid, real_gid) = real_uid_and_gid();
        let default_permissions = DirectoryPermissions {
            mode: DEFAULT_MODE,
            uid: real_uid,
            gid: real_gid,
        };

        let permissions = FusePermissions::parse(toml_source).unwrap();

        assert_eq!(permissions.holding_registers, default_permissions);
        assert_eq!(permissions.transactions, default_permissions);
        assert_eq!(permissions.report, default_permissions);
    }

    #[test]
    fn parse_rejects_a_client_trust_key() {
        let toml_source = r#"
            [client-trust]
            mode = 0o700
        "#;
        assert!(FusePermissions::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_an_unknown_top_level_key() {
        assert!(FusePermissions::parse("[nonsense]\nmode = 0o755\n").is_err());
    }

    #[test]
    fn parse_rejects_an_unknown_field_inside_a_directory_section() {
        let toml_source = r#"
            [transactions]
            owner = "root"
        "#;
        assert!(FusePermissions::parse(toml_source).is_err());
    }

    #[test]
    fn parse_rejects_invalid_toml_syntax() {
        assert!(FusePermissions::parse("this is not valid toml [[[").is_err());
    }
}
