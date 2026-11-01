use z8run_browser::session::UiSession;

#[test]
fn autolock_und_offline() {
    let mut s = UiSession::new(0);
    s.login(vec![9u8; 32]);
    assert!(!s.check_lock(299_000));
    assert!(s.check_lock(300_000));
    assert!(s.master().is_empty(), "Master nach Lock nicht genullt");
    s.login(vec![8u8; 32]);
    s.set_autolock(0);
    assert!(!s.check_lock(999_999_999), "0 = aus");
    assert!(!s.s3_probe(false));
    assert!(s.is_shutdown());
    assert!(!s.write_allowed());
    assert!(s.master().is_empty());
}
