//! Format-stability test: a v1 vault written by an earlier build must keep
//! opening with every future build. If this test fails, you broke users'
//! vaults — add a migration instead of changing the fixture.
//!
//! Regenerate (only when intentionally creating a new format version):
//! `cargo test -p keyward-core --test golden_vault -- --ignored`

use keyward_core::{
    ExposeSecret, ItemKind, KdfParams, Login, SecretString, Totp, UnlockedVault, VaultFile,
};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1.kwv");
const PASSWORD: &str = "correct horse battery staple";

fn floor_params() -> KdfParams {
    KdfParams {
        m_cost_kib: KdfParams::MIN_M_COST_KIB,
        t_cost: KdfParams::MIN_T_COST,
        p_cost: 1,
    }
}

#[test]
fn v1_fixture_still_opens() {
    let bytes = std::fs::read(FIXTURE).expect("fixture present");
    let file = VaultFile::from_bytes(&bytes).unwrap();
    assert_eq!(file.header().kdf.params, floor_params());
    assert_eq!(file.revision(), 2);

    let vault = file
        .unlock(&SecretString::from(PASSWORD.to_owned()))
        .unwrap();
    let items = vault.list();
    assert_eq!(items.len(), 2);

    let gh = items[0].kind.as_login().unwrap();
    assert_eq!(gh.title, "GitHub");
    assert_eq!(gh.username, "octocat");
    assert_eq!(gh.password.expose_secret(), "n3w-p4ssw0rd");
    assert_eq!(gh.url.as_deref(), Some("https://github.com"));
    assert_eq!(gh.notes.expose_secret(), "recovery codes: in the safe");
    assert_eq!(gh.tags, ["dev", "work"]);
    assert_eq!(gh.history.len(), 1);
    assert_eq!(gh.history[0].password.expose_secret(), "0ld-p4ssw0rd");
    assert_eq!(items[0].version, 2);
    let totp = Totp::parse(gh.totp.as_ref().unwrap().expose_secret()).unwrap();
    assert_eq!(totp.code_at(59).expose_secret(), "287082");

    let mail = items[1].kind.as_login().unwrap();
    assert_eq!(mail.title, "Mail");
    assert_eq!(mail.url, None);
    assert!(mail.totp.is_none());

    assert!(
        file.unlock(&SecretString::from("wrong".to_owned()))
            .is_err()
    );
}

#[test]
#[ignore = "writes the fixture; run manually only for a new format version"]
fn regenerate_fixture() {
    let mut v =
        UnlockedVault::create(&SecretString::from(PASSWORD.to_owned()), floor_params()).unwrap();
    let mut gh = Login::new(
        "GitHub",
        "octocat",
        SecretString::from("0ld-p4ssw0rd".to_owned()),
    );
    gh.url = Some("https://github.com".into());
    gh.notes = SecretString::from("recovery codes: in the safe".to_owned());
    gh.tags = vec!["dev".into(), "work".into()];
    gh.totp = Some(SecretString::from(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned(),
    ));
    let id = v.add(ItemKind::Login(gh));
    v.add(ItemKind::Login(Login::new(
        "Mail",
        "me@example.com",
        SecretString::from("m41l".to_owned()),
    )));
    v.seal().unwrap();
    v.update(id, |k| {
        k.as_login_mut().unwrap().password = SecretString::from("n3w-p4ssw0rd".to_owned());
    })
    .unwrap();
    let bytes = v.seal().unwrap().to_bytes().unwrap();
    std::fs::write(FIXTURE, bytes).unwrap();
}
