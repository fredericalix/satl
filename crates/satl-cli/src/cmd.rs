// SPDX-License-Identifier: BSD-2-Clause
//! One module per docker-compatible verb.

pub mod build;
pub mod ca;
pub mod compose;
pub mod config;
pub mod containers;
pub mod exec;
pub mod images;
pub mod inspect;
pub mod logs;
pub mod network;
pub mod node;
pub mod ps;
pub mod pull;
pub mod push;
pub mod run;
pub mod secret;
pub mod service;
pub mod stack;
pub mod swarm;
pub mod system;
pub mod tag;
pub mod volume;

/// Exit code for "the command itself failed", as docker uses it.
pub const FAILURE: u8 = 1;

/// Turn a container/exec status into a process exit code the way docker does:
/// the status is passed through, clamped into the byte a process can carry.
pub fn exit_code(status: i64) -> u8 {
    u8::try_from(status.clamp(0, i64::from(u8::MAX))).unwrap_or(FAILURE)
}

#[cfg(test)]
mod tests {
    use super::exit_code;

    #[test]
    fn exit_codes_are_clamped_into_a_byte() {
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(1), 1);
        assert_eq!(exit_code(137), 137);
        assert_eq!(exit_code(255), 255);
        assert_eq!(exit_code(300), 255);
        assert_eq!(exit_code(-1), 0);
    }
}
