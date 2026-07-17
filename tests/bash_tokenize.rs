//! Bash tokenizer + env-stripping unit tests (§8.2, §8.3).

use permcheck::bash::{RedirectKind, Token, strip_env_assignments, tokenize};

#[test]
fn words_and_quotes() {
    let toks = tokenize(r#"grep -i "some pattern" file.txt"#);
    assert_eq!(
        toks,
        vec![
            Token::Word("grep".into()),
            Token::Word("-i".into()),
            Token::Word("some pattern".into()),
            Token::Word("file.txt".into()),
        ]
    );
}

#[test]
fn redirection_targets() {
    let toks = tokenize("cat < in.txt > out.txt >> log");
    assert!(toks.contains(&Token::Redirect(RedirectKind::In, "in.txt".into())));
    assert!(toks.contains(&Token::Redirect(RedirectKind::Out, "out.txt".into())));
    assert!(toks.contains(&Token::Redirect(RedirectKind::Append, "log".into())));
}

#[test]
fn fd_dup_is_not_a_file_redirect() {
    let toks = tokenize("cmd 2>&1");
    assert!(!toks.iter().any(|t| matches!(t, Token::Redirect(_, _))));
}

#[test]
fn amp_redirect_to_filename_counts() {
    let toks = tokenize("cmd >&out.log");
    assert!(toks.contains(&Token::Redirect(RedirectKind::AmpOut, "out.log".into())));
}

#[test]
fn strips_leading_env_assignments() {
    assert_eq!(strip_env_assignments("FOO=bar BAZ=qux cat x"), "cat x");
    assert_eq!(strip_env_assignments("cat x"), "cat x");
    assert_eq!(strip_env_assignments(r#"FOO="a b" cmd"#), "cmd");
}

#[test]
fn env_stripping_stops_at_the_command() {
    // Stops at the first non-assignment word; a value that looks like a command
    // is not itself stripped.
    assert_eq!(
        strip_env_assignments("A=1 B=2 sudo cat .env"),
        "sudo cat .env"
    );
    assert_eq!(strip_env_assignments("PATH=/x:/y ls"), "ls");
    // `=` inside a quoted value does not start a new assignment.
    assert_eq!(strip_env_assignments(r#"K="a=b" run"#), "run");
}

#[test]
fn amp_append_and_fd_close_are_classified() {
    // `&>>` to a filename is an appending write.
    assert!(
        tokenize("cmd &>> out.log")
            .contains(&Token::Redirect(RedirectKind::AmpAppend, "out.log".into()))
    );
    // `>&-` closes an fd — not a file write.
    assert!(
        !tokenize("cmd >&-")
            .iter()
            .any(|t| matches!(t, Token::Redirect(_, _)))
    );
}

#[test]
fn spaced_redirection_target_is_read() {
    // The operator and its target may be separated by whitespace.
    assert!(
        tokenize("cat >   out.txt").contains(&Token::Redirect(RedirectKind::Out, "out.txt".into()))
    );
}
