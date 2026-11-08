//! The programs that make and check filesystems: those a recovery ramdisk
//! carries, and those only the installed system has, which run against
//! that system's own libraries.

use anyhow::{Context, Result};
use std::fmt;
use std::path::{Path, PathBuf};

/// Where the recovery's own programs are.
const BIN: &str = "/system/bin";

/// Where the installed system keeps the programs a recovery ramdisk does
/// not carry, as a recovery mounts that system, and the directories they
/// load libraries from: the system's own first, since they were built
/// against them, then the recovery's.
const SYSTEM_BIN: &str = "/mnt/system/system/bin";
pub const SYSTEM_LIB64: &str = "/mnt/system/system/lib64";
const SYSTEM_LIBRARIES: [&str; 2] = [SYSTEM_LIB64, RECOVERY_LIB64];

/// Where the recovery's own libraries are.
pub const RECOVERY_LIB64: &str = "/system/lib64";

/// The partition the installed system's programs come from, as the mount
/// page names it.
pub const SYSTEM: &str = "system";

/// A program to run on a filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    pub program: PathBuf,
    /// The directories it loads libraries from, for one of the installed
    /// system's.
    pub libraries: Vec<String>,
}

/// Why a program is not there to be run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// Only the installed system has it, and that system is not mounted.
    Unmounted(&'static str),
    /// Neither the recovery nor the installed system has it.
    Absent(String),
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Missing::Unmounted(base) => write!(
                f,
                "the {base} partition, which holds the program, is not mounted"
            ),
            Missing::Absent(name) => write!(
                f,
                "neither the recovery nor the installed system has {name}"
            ),
        }
    }
}

impl std::error::Error for Missing {}

/// How a program ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// Its exit status.
    pub status: i32,
    /// What it printed, its two outputs as one.
    pub said: String,
}

/// The program `name`: the recovery's own, or the installed system's for
/// one the recovery does not carry.
pub fn find(name: &str) -> Result<Tool, Missing> {
    look(name, Path::new(BIN), Path::new(SYSTEM_BIN))
}

fn look(name: &str, bin: &Path, system_bin: &Path) -> Result<Tool, Missing> {
    let own = bin.join(name);
    if own.exists() {
        return Ok(Tool {
            program: own,
            libraries: Vec::new(),
        });
    }
    let installed = system_bin.join(name);
    if installed.exists() {
        return Ok(Tool {
            program: installed,
            libraries: SYSTEM_LIBRARIES.map(str::to_string).to_vec(),
        });
    }
    // An unmounted system holds its programs out of reach rather than not
    // having them.
    match system_bin.is_dir() {
        true => Err(Missing::Absent(name.to_string())),
        false => Err(Missing::Unmounted(SYSTEM)),
    }
}

impl Tool {
    /// Run the program with `args` and give how it ended.
    pub fn run(&self, args: &[String]) -> Result<Ran> {
        let mut command = std::process::Command::new(&self.program);
        command.args(args);
        if !self.libraries.is_empty() {
            command.env("LD_LIBRARY_PATH", self.libraries.join(":"));
        }
        let out = command
            .output()
            .with_context(|| format!("run {}", self.describe(args)))?;
        let status = out
            .status
            .code()
            .with_context(|| format!("{} ended with {}", self.describe(args), out.status))?;
        let said = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        Ok(Ran { status, said })
    }

    /// The program and its arguments as one line, for an error to name.
    pub fn describe(&self, args: &[String]) -> String {
        let mut parts = vec![self.program.display().to_string()];
        parts.extend(args.iter().cloned());
        parts.join(" ")
    }
}

/// The path `device` as the programs take it.
pub fn path(device: &Path) -> Result<String> {
    device
        .to_str()
        .map(str::to_string)
        .with_context(|| format!("{} is not a path in UTF-8", device.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(name: &str) -> (PathBuf, PathBuf) {
        let top = std::env::temp_dir().join(format!("skyward-tools-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&top);
        std::fs::create_dir_all(top.join("bin")).unwrap();
        (top.join("bin"), top.join("system/bin"))
    }

    #[test]
    fn the_recoverys_own_program_comes_first_and_needs_none_of_the_systems_libraries() {
        let (bin, system_bin) = dirs("own");
        std::fs::create_dir_all(&system_bin).unwrap();
        for dir in [&bin, &system_bin] {
            std::fs::write(dir.join("fsck.f2fs"), []).unwrap();
        }
        let found = look("fsck.f2fs", &bin, &system_bin).unwrap();
        assert_eq!(
            found,
            Tool {
                program: bin.join("fsck.f2fs"),
                libraries: Vec::new()
            }
        );
    }

    #[test]
    fn a_program_only_the_installed_system_has_runs_against_its_libraries() {
        let (bin, system_bin) = dirs("installed");
        std::fs::create_dir_all(&system_bin).unwrap();
        std::fs::write(system_bin.join("e2fsck"), []).unwrap();
        let found = look("e2fsck", &bin, &system_bin).unwrap();
        assert_eq!(found.program, system_bin.join("e2fsck"));
        assert_eq!(
            found.libraries,
            ["/mnt/system/system/lib64", "/system/lib64"]
        );
        assert_eq!(
            look("tune2fs", &bin, &system_bin),
            Err(Missing::Absent("tune2fs".into()))
        );
    }

    #[test]
    fn an_unmounted_system_holds_its_programs_out_of_reach() {
        let (bin, system_bin) = dirs("unmounted");
        assert_eq!(
            look("e2fsck", &bin, &system_bin),
            Err(Missing::Unmounted("system"))
        );
    }

    #[test]
    fn a_program_is_named_with_its_arguments() {
        let tool = Tool {
            program: PathBuf::from("/system/bin/fsck.f2fs"),
            libraries: Vec::new(),
        };
        assert_eq!(
            tool.describe(&["-f".into(), "/dev/block/dm-8".into()]),
            "/system/bin/fsck.f2fs -f /dev/block/dm-8"
        );
    }
}
