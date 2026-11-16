//! End-to-end sync: a real keyward-server on a random localhost port and
//! two "devices" (separate vault files) driven through the `kw` binary.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use tempfile::TempDir;

const MASTER: &str = "sync-master-pw";

/// One server per test binary, started on first use.
fn server_url() -> &'static str {
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let mut cfg = keyward_server::Config::for_tests();
                cfg.auth_rate_per_min = 10_000;
                let app = keyward_server::build(cfg, keyward_server::system_clock())
                    .await
                    .unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                axum::serve(
                    listener,
                    app.router
                        .into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
        });
        format!("http://{}", rx.recv().unwrap())
    })
}

struct Device {
    _dir: TempDir,
    vault: PathBuf,
}

impl Device {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kwv");
        Self { _dir: dir, vault }
    }

    fn run(&self, args: &[&str], stdin: &[&str]) -> assert_cmd::assert::Assert {
        run_at(&self.vault, args, stdin)
    }

    fn init(&self) -> &Self {
        self.run(
            &["init", "--kdf-memory-mib", "19", "--kdf-iterations", "2"],
            &[MASTER, MASTER],
        )
        .success();
        self
    }

    fn add(&self, title: &str, pw: &str) -> &Self {
        self.run(&["add", title], &[MASTER, pw, pw]).success();
        self
    }

    fn password(&self, title: &str) -> String {
        let out = self
            .run(&["get", title, "--show"], &[MASTER])
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap().trim_end().to_owned()
    }

    fn sync(&self) -> assert_cmd::assert::Assert {
        self.run(&["sync"], &[MASTER])
    }
}

fn run_at(vault: &Path, args: &[&str], stdin: &[&str]) -> assert_cmd::assert::Assert {
    let mut input = stdin.join("\n");
    input.push('\n');
    Command::cargo_bin("kw")
        .unwrap()
        .env("KW_VAULT", vault)
        .arg("--password-stdin")
        .args(args)
        .write_stdin(input)
        .assert()
}

fn unique_user(tag: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    )
}

fn clone_into(dev: &Device, user: &str) -> assert_cmd::assert::Assert {
    dev.run(
        &[
            "sync",
            "clone",
            "--server",
            server_url(),
            "--username",
            user,
        ],
        &[MASTER],
    )
}

#[test]
fn register_clone_edit_delete_round_trip() {
    let user = unique_user("alice");
    let a = Device::new();
    a.init().add("GitHub", "gh-1").add("Mail", "mail-1");
    a.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .success()
    .stdout(contains("Registered").and(contains("sent 2")));

    let b = Device::new();
    clone_into(&b, &user)
        .success()
        .stdout(contains("Cloned vault").and(contains("2 item(s)")));
    assert_eq!(b.password("github"), "gh-1");

    // edit on B, propagate to A
    b.run(&["edit", "github", "--password"], &[MASTER, "gh-2", "gh-2"])
        .success();
    b.sync().success().stdout(contains("sent 1"));
    a.sync().success().stdout(contains("received 1"));
    assert_eq!(a.password("github"), "gh-2");

    // delete on A, propagate to B
    a.run(&["rm", "mail", "--yes"], &[MASTER]).success();
    a.sync().success().stdout(contains("deleted 1 on server"));
    b.sync().success().stdout(contains("removed 1"));
    b.run(&["get", "mail", "--show"], &[MASTER])
        .failure()
        .stderr(contains("no item matches"));

    // nothing pending afterwards
    a.run(&["sync", "status"], &[MASTER])
        .success()
        .stdout(contains("Pending:  0 to send, 0 deletion(s)"))
        .stdout(contains(&user));
}

#[test]
fn concurrent_edits_converge() {
    let user = unique_user("conflict");
    let a = Device::new();
    a.init().add("Shared", "base");
    a.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .success();
    let b = Device::new();
    clone_into(&b, &user).success();

    a.run(
        &["edit", "shared", "--password"],
        &[MASTER, "from-a", "from-a"],
    )
    .success();
    std::thread::sleep(std::time::Duration::from_millis(20));
    b.run(
        &["edit", "shared", "--password"],
        &[MASTER, "from-b", "from-b"],
    )
    .success();
    a.sync().success();
    b.sync()
        .success()
        .stdout(contains("1 conflict(s) resolved"));
    a.sync().success();
    assert_eq!(a.password("shared"), "from-b", "last writer wins");
    assert_eq!(b.password("shared"), "from-b");
}

#[test]
fn clone_with_wrong_password_creates_nothing() {
    let user = unique_user("bob");
    let a = Device::new();
    a.init();
    a.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .success();
    let b = Device::new();
    b.run(
        &[
            "sync",
            "clone",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &["not-the-password"],
    )
    .failure()
    .stderr(contains("rejected the login"));
    assert!(!b.vault.exists());
}

#[test]
fn insecure_urls_and_duplicate_registration_are_refused() {
    let a = Device::new();
    a.init();
    a.run(
        &[
            "sync",
            "register",
            "--server",
            "http://example.com",
            "--username",
            "x",
        ],
        &[MASTER],
    )
    .failure()
    .stderr(contains("https://"));

    let user = unique_user("dup");
    a.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .success();
    a.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .failure()
    .stderr(contains("already connected"));

    let b = Device::new();
    b.init();
    b.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .failure()
    .stderr(contains("already taken"));
}

#[test]
fn change_master_password_updates_server() {
    let user = unique_user("carol");
    let a = Device::new();
    a.init().add("Item", "secret");
    a.run(
        &[
            "sync",
            "register",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &[MASTER],
    )
    .success();
    let b = Device::new();
    clone_into(&b, &user).success();

    a.run(
        &["change-master-password"],
        &[MASTER, "new-master-pw", "new-master-pw"],
    )
    .success()
    .stdout(contains("on the sync server"));
    a.run(&["sync"], &["new-master-pw"]).success();

    // B still has the old password locally; the server refuses it now.
    b.sync().failure().stderr(contains("kw sync clone"));

    // A fresh clone with the new password works.
    let c = Device::new();
    c.run(
        &[
            "sync",
            "clone",
            "--server",
            server_url(),
            "--username",
            &user,
        ],
        &["new-master-pw"],
    )
    .success();
    let out = c
        .run(&["get", "item", "--show"], &["new-master-pw"])
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim_end(), "secret");
}

#[test]
fn sync_inside_shell_and_disconnect() {
    let user = unique_user("dora");
    let a = Device::new();
    a.init();
    a.run(
        &["shell"],
        &[
            MASTER,
            &format!("sync register --server {} --username {user}", server_url()),
            "add Later -u x --generate",
            "sync",
            "sync clone --server http://127.0.0.1:1 --username nope",
            "exit",
        ],
    )
    .success()
    .stdout(contains("Registered").and(contains("sent 1")))
    .stderr(contains("outside the shell"));

    a.run(&["sync", "disconnect"], &[MASTER])
        .success()
        .stdout(contains("Disconnected"));
    a.run(&["sync"], &[MASTER])
        .failure()
        .stderr(contains("not connected"));
}
