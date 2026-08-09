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
fn clobber_override_is_one_operator() {
    // The `|` of `>|` belongs to the redirection, so the target stays in the
    // same unit as the command that writes it.
    assert_eq!(split("echo x >| f"), ["echo x >| f"]);
    assert_eq!(split("echo x >|f"), ["echo x >|f"]);
    assert_eq!(split("echo x 1>| f"), ["echo x 1>| f"]);
    // A real pipe after a completed redirection still splits.
    assert_eq!(split("echo x > f | grep y"), ["echo x > f", "grep y"]);
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
fn extracts_substitutions_from_arithmetic_expansion() {
    // Bash expands a substitution inside `$(( … ))`, so the splitter lifts it
    // out as its own unit rather than stepping over the whole expansion.
    assert!(
        split("echo $(( $(rm -rf /) ))")
            .iter()
            .any(|u| u == "rm -rf /")
    );
    assert!(split("echo $(( `id` ))").iter().any(|u| u == "id"));
    // Arithmetic with no substitution still yields no interior unit.
    assert_eq!(split("echo $(( 1 + 2 ))"), ["echo $(( 1 + 2 ))"]);
}

#[test]
fn extracts_from_backticks_and_process_substitution() {
    assert!(split("echo `id`").iter().any(|u| u == "id"));
    assert!(split("diff <(cat a) <(cat b)").iter().any(|u| u == "cat a"));
}

#[test]
fn subshell_parens_bound_a_unit() {
    // A `(` in command position and every `)` are unit boundaries, so the
    // subshell's contents are decided as their own command.
    assert_eq!(split("(rm -rf /)"), ["rm -rf /"]);
    assert_eq!(split("( rm -rf / )"), ["rm -rf /"]);
    assert_eq!(split("echo a | (rm -rf /)"), ["echo a", "rm -rf /"]);
    assert_eq!(split("(cd /tmp && rm -rf x)"), ["cd /tmp", "rm -rf x"]);
    // Unterminated: the command is still a unit rather than being swallowed.
    assert_eq!(split("((rm -rf /"), ["rm -rf /"]);
    // A `)` closing a case pattern exposes the branch body the same way.
    assert_eq!(
        split("case x in a) rm -rf /;; esac"),
        ["case x in a", "rm -rf /", "esac"]
    );
}

#[test]
fn a_paren_outside_command_position_is_word_content() {
    // Only a `(` the shell would read as a subshell opener splits. Anywhere else
    // it belongs to the word, so an array assignment and a format specifier keep
    // their shape instead of fragmenting into units that match no rule.
    assert_eq!(split("arr=(a b c)"), ["arr=(a b c"]);
    assert_eq!(
        split("git log --format=%(refname)"),
        ["git log --format=%(refname"]
    );
    assert_eq!(split(r"find . \( -name a \)"), [r"find . \( -name a \)"]);
    assert_eq!(split(r#"echo "(quoted)""#), [r#"echo "(quoted)""#]);
    assert_eq!(split("echo '(quoted)'"), ["echo '(quoted)'"]);
    // The three substitution forms claim their own parens before this arm runs,
    // so each keeps yielding the inner command plus the undivided outer text.
    assert_eq!(split("echo $(id)"), ["id", "echo $(id)"]);
    assert_eq!(split("diff <(cat a) b"), ["cat a", "diff <(cat a) b"]);
    assert_eq!(split("echo $((1 + 2))"), ["echo $((1 + 2))"]);
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
fn unquoted_comment_is_stripped() {
    // A `#` starting a word opens a comment bash discards to end of line, so the
    // matched unit must drop it too.
    assert_eq!(
        split("aws ec2 terminate-instances # describe-instances"),
        ["aws ec2 terminate-instances"]
    );
    assert_eq!(split("ls # comment\nrm -rf /"), ["ls", "rm -rf /"]);
}

#[test]
fn hash_inside_a_word_is_not_a_comment() {
    // `#` mid-token (a fragment, an anchor) is an ordinary character.
    assert_eq!(
        split("git checkout feature#123"),
        ["git checkout feature#123"]
    );
    assert_eq!(split("echo a#b"), ["echo a#b"]);
}

#[test]
fn quoted_hash_is_not_a_comment() {
    assert_eq!(split("echo '# not a comment'"), ["echo '# not a comment'"]);
    assert_eq!(split("echo \"# also not\""), ["echo \"# also not\""]);
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
