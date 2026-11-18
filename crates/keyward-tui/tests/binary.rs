//! The `keyward` binary: TUI without a command, `kw` commands with one.

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

fn keyward() -> Command {
    Command::cargo_bin("keyward").unwrap()
}

#[test]
fn help_lists_kw_commands() {
    keyward().arg("--help").assert().success().stdout(
        contains("terminal UI")
            .and(contains("add"))
            .and(contains("sync")),
    );
}

#[test]
fn runs_kw_commands() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.kwv");
    let run = |args: &[&str], stdin: &str| {
        keyward()
            .env("KW_VAULT", &vault)
            .arg("--password-stdin")
            .args(args)
            .write_stdin(stdin.to_owned())
            .assert()
    };
    run(
        &["init", "--kdf-memory-mib", "19", "--kdf-iterations", "2"],
        "master-pw-1\nmaster-pw-1\n",
    )
    .success();
    run(
        &["add", "GitHub", "-u", "me"],
        "master-pw-1\nsecret-1\nsecret-1\n",
    )
    .success();
    run(&["get", "github", "--show"], "master-pw-1\n")
        .success()
        .stdout(contains("secret-1"));
    run(&["gen", "-l", "12"], "").success();
}

#[test]
fn tui_without_vault_explains() {
    let dir = tempfile::tempdir().unwrap();
    keyward()
        .env("KW_VAULT", dir.path().join("missing.kwv"))
        .assert()
        .failure()
        .stderr(contains("keyward init"));
}
