//! Bash splitter unit tests (§8.1).

use permcheck::bash::split;

#[test]
fn splits_on_operators() {
    assert_eq!(split("a && b || c | d ; e"), ["a", "b", "c", "d", "e"]);
}

#[test]
fn newlines_are_separators() {
    assert_eq!(split("a\nb\nc"), ["a", "b", "c"]);
}

#[test]
fn single_quotes_suppress_splitting() {
    assert_eq!(split("echo 'a && b'"), ["echo 'a && b'"]);
}

#[test]
fn extracts_command_substitution_as_unit() {
    let units = split("echo $(rm -rf /)");
    assert!(units.iter().any(|u| u.contains("rm -rf /")));
}

#[test]
fn extracts_from_backticks_and_process_substitution() {
    assert!(split("echo `id`").iter().any(|u| u == "id"));
    assert!(split("diff <(cat a) <(cat b)").iter().any(|u| u == "cat a"));
}

#[test]
fn redirection_amp_is_not_a_background_split() {
    // `2>&1` and `>file` must not split the command.
    assert_eq!(split("cmd arg 2>&1"), ["cmd arg 2>&1"]);
    assert_eq!(split("cmd > out.txt"), ["cmd > out.txt"]);
}

#[test]
fn unterminated_is_total_not_error() {
    // Consumed to end of input; never panics.
    let _ = split("echo $(cat");
    let _ = split("echo 'unterminated");
    let _ = split("echo `id");
    let _ = split("a && b || $(");
}

#[test]
fn arithmetic_is_literal_not_a_command() {
    // `$(( … ))` is arithmetic, not a command substitution: nothing is extracted.
    assert_eq!(split("echo $((1+2))"), ["echo $((1+2))"]);
    assert!(
        !split("echo $((1+2))")
            .iter()
            .any(|u| u.contains("1+2") && u != "echo $((1+2))")
    );
}

#[test]
fn substitution_inside_double_quotes_is_extracted() {
    assert!(
        split(r#"echo "$(cat .env)""#)
            .iter()
            .any(|u| u == "cat .env")
    );
    assert!(split(r#"echo "`id`""#).iter().any(|u| u == "id"));
}

#[test]
fn deeply_nested_substitution_extracts_inner() {
    assert!(
        split("echo $(echo $(echo $(id)))")
            .iter()
            .any(|u| u == "id")
    );
}

#[test]
fn escaped_quote_does_not_open_a_quoted_region() {
    // An unquoted `\"` / `\'` is a literal quote, not a delimiter, so it must not
    // suppress the following split points. Regression for the escaped-quote
    // splitter bypass.
    assert_eq!(
        split(r#"ls \" ; rm -rf /tmp/x"#),
        [r#"ls \""#, "rm -rf /tmp/x"]
    );
    assert_eq!(
        split(r#"ls \' ; rm -rf /tmp/x"#),
        [r#"ls \'"#, "rm -rf /tmp/x"]
    );
    // A backslash-escaped operator is literal and must NOT split (`a&&b` is one
    // word); the escaped bytes stay attached.
    assert_eq!(split(r"echo a\&\&b"), [r"echo a\&\&b"]);
    // An escaped `"` *inside* a real double-quoted string does not close it, so
    // the `;` stays quoted and does not split.
    assert_eq!(split(r#"echo "a \" ; b""#), [r#"echo "a \" ; b""#]);
}

#[test]
fn process_substitution_output_form_is_extracted() {
    assert!(
        split("tee >(grep secret)")
            .iter()
            .any(|u| u == "grep secret")
    );
}
