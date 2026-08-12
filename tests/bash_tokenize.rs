//! Bash tokenizer + env-stripping unit tests (§8.2, §8.3).

use permcheck::bash::{RedirectKind, Token, strip_env_assignments, tokenize};

/// The word values of a command, redirections excluded.
fn words(s: &str) -> Vec<String> {
    tokenize(s)
        .into_iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word),
            Token::Redirect(..) => None,
        })
        .collect()
}

/// A command's redirections as kind and target.
fn redirects(s: &str) -> Vec<(RedirectKind, String)> {
    tokenize(s)
        .into_iter()
        .filter_map(|token| match token {
            Token::Redirect(kind, target) => Some((kind, target)),
            Token::Word(_) => None,
        })
        .collect()
}

#[test]
fn words_and_quotes() {
    assert_eq!(
        words(r#"grep -i "some pattern" file.txt"#),
        ["grep", "-i", "some pattern", "file.txt"]
    );
}

#[test]
fn ansi_c_and_locale_quotes_keep_spaced_words_together() {
    let expected = ["/tmp/my tool/bin/rm", "-rf", "x"];
    assert_eq!(words(r#"$'/tmp/my tool/bin/rm' -rf x"#), expected);
    assert_eq!(words(r#"$"/tmp/my tool/bin/rm" -rf x"#), expected);
    assert_eq!(
        words(r#""/tmp/a\" b/bin/rm" -rf x"#),
        ["/tmp/a\" b/bin/rm", "-rf", "x"]
    );
}

#[test]
fn redirection_targets() {
    assert_eq!(
        redirects("cat < in.txt > out.txt >> log"),
        [
            (RedirectKind::In, "in.txt".to_string()),
            (RedirectKind::Out, "out.txt".to_string()),
            (RedirectKind::Append, "log".to_string()),
        ]
    );
}

#[test]
fn fd_dup_is_not_a_file_redirect() {
    assert!(redirects("cmd 2>&1").is_empty());
}

#[test]
fn amp_redirect_to_filename_counts() {
    assert_eq!(
        redirects("cmd >&out.log"),
        [(RedirectKind::AmpOut, "out.log".to_string())]
    );
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
    assert_eq!(
        redirects("cmd &>> out.log"),
        [(RedirectKind::AmpAppend, "out.log".to_string())]
    );
    // `>&-` closes an fd, not a file write.
    assert!(redirects("cmd >&-").is_empty());
}

#[test]
fn spaced_redirection_target_is_read() {
    // The operator and its target may be separated by whitespace.
    assert_eq!(
        redirects("cat >   out.txt"),
        [(RedirectKind::Out, "out.txt".to_string())]
    );
}
