//! End-to-end tests of the `kw` binary. Passwords are fed with
//! `--password-stdin`; vaults use the minimum allowed KDF cost to stay fast.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use tempfile::TempDir;

const MASTER: &str = "master-pass-123";

struct Env {
    dir: TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn vault(&self) -> PathBuf {
        self.dir.path().join("v.kwv")
    }

    fn kw(&self) -> Command {
        let mut c = Command::cargo_bin("kw").unwrap();
        c.env("KW_VAULT", self.vault()).arg("--password-stdin");
        c
    }

    /// Run `kw <args>` with the given stdin lines.
    fn run(&self, args: &[&str], stdin_lines: &[&str]) -> assert_cmd::assert::Assert {
        let mut input = stdin_lines.join("\n");
        input.push('\n');
        self.kw().args(args).write_stdin(input).assert()
    }

    fn init(&self) -> &Self {
        self.run(
            &["init", "--kdf-memory-mib", "19", "--kdf-iterations", "2"],
            &[MASTER, MASTER],
        )
        .success()
        .stdout(contains("Created vault"));
        self
    }

    fn add(&self, title: &str, user: &str, pw: &str) -> &Self {
        self.run(&["add", title, "-u", user], &[MASTER, pw, pw])
            .success();
        self
    }

    fn get(&self, query: &str, field: &str) -> String {
        let out = self
            .run(&["get", query, "--field", field, "--show"], &[MASTER])
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap().trim_end().to_owned()
    }
}

fn file_text(p: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(p).unwrap()).into_owned()
}

#[test]
fn init_then_refuse_overwrite() {
    let e = Env::new();
    e.init();
    assert!(e.vault().exists());
    e.run(&["init"], &[MASTER, MASTER])
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn init_validates_master_password() {
    let e = Env::new();
    e.run(&["init"], &["short", "short"])
        .failure()
        .stderr(contains("at least 8"));
    e.run(&["init"], &["long-enough-1", "long-enough-2"])
        .failure()
        .stderr(contains("did not match"));
    e.run(&["init", "--kdf-memory-mib", "1"], &[])
        .failure()
        .stderr(contains("invalid KDF parameters"));
    assert!(!e.vault().exists());
}

#[test]
fn missing_vault_points_to_init() {
    Env::new()
        .run(&["list"], &[MASTER])
        .failure()
        .stderr(contains("kw init"));
}

#[test]
fn add_get_list_search() {
    let e = Env::new();
    e.init();
    e.run(
        &[
            "add",
            "GitHub",
            "-u",
            "octocat",
            "--url",
            "https://github.com",
            "-t",
            "work",
        ],
        &[MASTER, "gh-secret-pw", "gh-secret-pw"],
    )
    .success()
    .stdout(contains("Added \"GitHub\""));
    e.add("Mail", "me@example.com", "mail-pw");

    assert_eq!(e.get("github", "password"), "gh-secret-pw");
    assert_eq!(e.get("GitHub", "username"), "octocat");
    assert_eq!(e.get("mail", "url"), "");

    e.run(&["list"], &[MASTER])
        .success()
        .stdout(
            contains("GitHub")
                .and(contains("Mail"))
                .and(contains("octocat")),
        )
        .stdout(contains("gh-secret-pw").not());
    e.run(&["list", "--tag", "WORK"], &[MASTER])
        .success()
        .stdout(contains("GitHub").and(contains("Mail").not()));
    e.run(&["search", "example.com"], &[MASTER])
        .success()
        .stdout(contains("Mail").and(contains("GitHub").not()));
    e.run(&["search", "nothing-here"], &[MASTER])
        .success()
        .stdout(contains("(no items)"));
}

#[test]
fn wrong_master_password_is_generic_and_leaks_nothing() {
    let e = Env::new();
    e.init().add("Bank", "me", "bank-pw");
    e.run(&["get", "Bank", "--show"], &["not-the-master"])
        .failure()
        .stderr(contains("wrong password or the vault is corrupted"))
        .stderr(contains("not-the-master").not())
        .stdout(contains("bank-pw").not());
}

#[test]
fn vault_file_holds_no_plaintext() {
    let e = Env::new();
    e.init().add("SuperSecretBank", "agent007", "TopSecretPw!");
    let text = file_text(&e.vault());
    for leak in ["SuperSecretBank", "agent007", "TopSecretPw", MASTER] {
        assert!(!text.contains(leak), "vault file contains {leak}");
    }
    assert!(text.starts_with("KWVT"));
}

#[test]
fn edit_records_history_and_updates_fields() {
    let e = Env::new();
    e.init().add("Site", "old-user", "pw-one");
    e.run(
        &[
            "edit",
            "site",
            "--password",
            "-u",
            "new-user",
            "--add-tag",
            "x",
            "--title",
            "Site 2",
        ],
        &[MASTER, "pw-two", "pw-two"],
    )
    .success()
    .stdout(contains("Updated \"Site 2\""));
    assert_eq!(e.get("Site 2", "password"), "pw-two");
    assert_eq!(e.get("Site 2", "username"), "new-user");
    let details = e.get("Site 2", "details");
    assert!(details.contains("1 previous password"), "{details}");
    assert!(details.contains("Version:   2"), "{details}");
    assert!(
        !details.contains("pw-two"),
        "details must not show the password"
    );

    e.run(&["edit", "Site 2"], &[MASTER])
        .failure()
        .stderr(contains("nothing to change"));
}

#[test]
fn edit_generate_replaces_password() {
    let e = Env::new();
    e.init().add("Gen", "u", "before");
    e.run(&["edit", "gen", "--generate", "--length", "40"], &[MASTER])
        .success();
    let pw = e.get("gen", "password");
    assert_eq!(pw.chars().count(), 40);
    assert_ne!(pw, "before");
}

#[test]
fn remove_with_and_without_confirmation() {
    let e = Env::new();
    e.init().add("Keep", "u", "p").add("Drop", "u", "p");
    e.run(&["rm", "drop"], &[MASTER, "n"])
        .success()
        .stdout(contains("Cancelled"));
    e.run(&["rm", "drop"], &[MASTER, "y"])
        .success()
        .stdout(contains("Deleted \"Drop\""));
    e.run(&["get", "drop", "--show"], &[MASTER])
        .failure()
        .stderr(contains("no item matches"));
    e.run(&["rm", "keep", "--yes"], &[MASTER]).success();
}

#[test]
fn ambiguous_query_lists_candidates_and_id_prefix_works() {
    let e = Env::new();
    e.init()
        .add("Google Work", "a", "p1")
        .add("Google Home", "b", "p2");
    e.run(&["get", "google", "--show"], &[MASTER])
        .failure()
        .stderr(contains("matches 2 items"))
        .stderr(contains("Google Work").and(contains("Google Home")));

    // exact title wins over substring matches
    assert_eq!(e.get("google home", "password"), "p2");

    // id prefix from the listing
    let list = e
        .run(&["list"], &[MASTER])
        .success()
        .get_output()
        .stdout
        .clone();
    let list = String::from_utf8(list).unwrap();
    let row = list.lines().find(|l| l.contains("Google Work")).unwrap();
    let id = row.split_whitespace().next().unwrap();
    assert_eq!(e.get(id, "password"), "p1");
}

#[test]
fn change_master_password_and_backups() {
    let e = Env::new();
    e.init().add("A", "u", "pa");
    e.run(
        &["change-master-password"],
        &[MASTER, "brand-new-master", "brand-new-master"],
    )
    .success()
    .stdout(contains("Master password changed"))
    .stderr(contains("OLD password"));

    e.run(&["list"], &[MASTER]).failure();
    e.run(&["get", "a", "--show"], &["brand-new-master"])
        .success()
        .stdout(contains("pa"));

    let bak1 = PathBuf::from(format!("{}.bak.1", e.vault().display()));
    assert!(bak1.exists(), "a backup is written on each save");
}

#[test]
fn totp_codes() {
    let e = Env::new();
    e.init();
    e.run(
        &["add", "2FA", "--totp"],
        &[MASTER, "pw", "pw", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"],
    )
    .success();
    let code = e.get("2fa", "totp");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    e.run(
        &["add", "Bad2FA", "--totp"],
        &[MASTER, "pw", "pw", "not base32 !!"],
    )
    .failure()
    .stderr(contains("TOTP"));
    e.run(&["get", "2fa", "-f", "totp", "--show"], &[MASTER])
        .success()
        .stderr(contains("valid for"));
}

#[test]
fn generator_needs_no_vault() {
    let e = Env::new();
    let out = e
        .run(&["gen", "-l", "32", "--no-symbols"], &[])
        .success()
        .stderr(contains("entropy:"))
        .get_output()
        .stdout
        .clone();
    let pw = String::from_utf8(out).unwrap();
    let pw = pw.trim_end();
    assert_eq!(pw.len(), 32);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

    let out = e
        .run(&["gen", "--passphrase", "-w", "5", "--separator", "_"], &[])
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        String::from_utf8(out)
            .unwrap()
            .trim_end()
            .split('_')
            .count(),
        5
    );

    e.run(&["gen", "-l", "2"], &[])
        .failure()
        .stderr(contains("invalid generator options"));
}

#[test]
fn interactive_shell_session() {
    let e = Env::new();
    e.init().add("Existing", "u", "pe");
    e.run(
        &["shell"],
        &[
            MASTER,
            "list",
            "add \"Shell Item\" -u alice --generate",
            "get 'shell item' -f username --show",
            "bogus-command",
            "lock",
            "get existing --show",
            MASTER,
            "exit",
            "list",
        ],
    )
    .success()
    .stdout(contains("Existing"))
    .stdout(contains("Added \"Shell Item\""))
    .stdout(contains("alice"))
    .stdout(contains("pe"))
    .stderr(contains("Locked."))
    .stderr(contains("unrecognized subcommand"));

    e.run(&["search", "shell"], &[MASTER])
        .success()
        .stdout(contains("Shell Item"));
}
