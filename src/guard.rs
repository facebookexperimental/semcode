// SPDX-License-Identifier: MIT OR Apache-2.0
//! The text of a preprocessor guard, as stored with a definition.
//!
//! A guard is the conjunction of the conditions of every `#if` arm that
//! encloses a definition, outermost first. Each conjunct is written so that it
//! can be read on its own: a single name (`CONFIG_X`, `defined(CONFIG_X)`), a
//! negated one, a parenthesized group, or a negated group. That makes the
//! guard a flat list of terms joined by ` && `, which is what lets two guards
//! be compared without evaluating either: two definitions in different arms
//! of one `#if` carry a term and its negation, and two definitions in
//! independent `#if`s do not.
//!
//! Nothing here evaluates a condition. A term is compared as text.

/// A condition as one conjunct of a guard: kept as written where it is one
/// term, parenthesized otherwise.
///
/// `&&` binds tighter than `||` and `?:`, so an outer arm reading
/// `!defined(CONFIG_PREEMPTION) || defined(CONFIG_PREEMPT_DYNAMIC)` joined
/// bare to an inner `defined(CONFIG_HAVE_PREEMPT_DYNAMIC_CALL)` reads as "not
/// preemptible, or dynamic with the call" -- a configuration no arm of
/// `sched.h` states. Redundant parentheses cost nothing; a missing pair
/// changes the configuration.
pub fn as_conjunct(condition: &str) -> String {
    if is_term(condition) {
        condition.to_string()
    } else {
        format!("({condition})")
    }
}

/// The term that holds exactly where `term` does not: the arm below an `#if`
/// is reached when its condition did not hold.
///
/// `term` must already be a conjunct (see [`as_conjunct`]). `!X` and `X` are
/// each other's negation, whichever of them the file wrote, so the arms of
/// `#ifndef X` / `#else` read `!defined(X)` and `defined(X)`.
pub fn negate_term(term: &str) -> String {
    if let Some(rest) = term.strip_prefix('!') {
        if is_atom(rest) || wholly_parenthesized(rest) {
            return rest.to_string();
        }
    }
    format!("!{}", as_conjunct(term))
}

/// The conjuncts of a guard, in order.
///
/// Splits on ` && ` only outside parentheses and character constants, which
/// is exact for a guard built from [`as_conjunct`] terms.
pub fn terms(guard: &str) -> Vec<&str> {
    let bytes = guard.as_bytes();
    let mut found = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\'' => {
                at = char_constant_end(bytes, at);
                continue;
            }
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'&' if depth == 0 && bytes.get(at + 1) == Some(&b'&') => {
                found.push(guard[start..at].trim());
                at += 2;
                start = at;
                continue;
            }
            _ => {}
        }
        at += 1;
    }
    found.push(guard[start..].trim());
    found.retain(|term| !term.is_empty());
    found
}

/// Whether no build can satisfy both guards: one of them holds a term whose
/// negation the other holds.
///
/// This is how the arms of one `#if` tell each other apart, so it proves
/// what it says. It is not the converse: two guards it cannot separate may
/// still be unsatisfiable together, because nothing here evaluates them.
pub fn excludes(left: &str, right: &str) -> bool {
    let right_terms = terms(right);
    terms(left)
        .iter()
        .any(|term| right_terms.contains(&negate_term(term).as_str()))
}

/// The terms of a guard a path can carry as facts: `defined(CONFIG_X)`,
/// `CONFIG_X`, and their negations.
///
/// Only Kconfig symbols. A configuration is one assignment of them for the
/// whole build, so a hop under `CONFIG_X` and a deeper hop under
/// `!CONFIG_X` cannot both run. Any other macro can be defined in one
/// translation unit and not in another (`DEBUG`, `MODULE`, a header's own
/// `#define`), so it proves nothing across a call. Disjunctions and other
/// compound terms are not facts either: they are kept whole, never split.
pub fn config_facts(guard: &str) -> Vec<String> {
    let mut facts = Vec::new();
    collect_facts(guard, &mut facts);
    facts
}

fn collect_facts(conjunction: &str, facts: &mut Vec<String>) {
    for term in terms(conjunction) {
        // A positive group that is itself only a conjunction asserts each
        // of its terms: `(defined(CONFIG_A) && defined(CONFIG_B))`. A group
        // with a top-level `||` or `?:` asserts none of them on its own.
        if wholly_parenthesized(term) {
            let inner = &term[1..term.len() - 1];
            if !has_top_level_choice(inner) {
                collect_facts(inner, facts);
            }
            continue;
        }
        let (negated, positive) = match term.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, term),
        };
        if !is_atom(positive) {
            continue;
        }
        let canonical = canonical_atom(positive);
        if !symbol_of(&canonical).starts_with("CONFIG_") {
            continue;
        }
        let fact = if negated {
            format!("!{canonical}")
        } else {
            canonical
        };
        if !facts.contains(&fact) {
            facts.push(fact);
        }
    }
}

/// The fact on the path that a guard contradicts, if there is one: a
/// Kconfig term of `guard` whose negation an enclosing hop asserted.
pub fn contradiction<'a>(facts: &[&'a str], guard: &str) -> Option<&'a str> {
    config_facts(guard).iter().find_map(|term| {
        let negation = match term.strip_prefix('!') {
            Some(positive) => positive.to_string(),
            None => format!("!{term}"),
        };
        facts.iter().copied().find(|fact| *fact == negation)
    })
}

/// One spelling per atom, so `defined CONFIG_X` and `defined(CONFIG_X)`
/// compare equal.
fn canonical_atom(atom: &str) -> String {
    match atom.strip_prefix("defined ") {
        Some(name) => format!("defined({})", name.trim()),
        None => atom.to_string(),
    }
}

/// The symbol an atom names: `CONFIG_X` for `defined(CONFIG_X)`,
/// `IS_ENABLED(CONFIG_X)` and `CONFIG_X`.
fn symbol_of(atom: &str) -> &str {
    match atom.split_once('(') {
        Some((_, rest)) => rest.strip_suffix(')').unwrap_or(rest).trim(),
        None => atom,
    }
}

/// Whether a condition has `||` or `?` outside parentheses: then its
/// `&&`-separated pieces are not conjuncts of the whole.
fn has_top_level_choice(condition: &str) -> bool {
    let bytes = condition.as_bytes();
    let mut depth = 0usize;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\'' => {
                at = char_constant_end(bytes, at);
                continue;
            }
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'?' if depth == 0 => return true,
            b'|' if depth == 0 && bytes.get(at + 1) == Some(&b'|') => return true,
            _ => {}
        }
        at += 1;
    }
    false
}

/// Whether a condition is one conjunct already: a name, a negated name, a
/// whole group, or a negated whole group.
fn is_term(condition: &str) -> bool {
    let positive = condition.strip_prefix('!').unwrap_or(condition);
    is_atom(positive) || wholly_parenthesized(positive)
}

/// Whether a condition is one name -- a bare `CONFIG_X`, `defined
/// CONFIG_X`, or a one-argument test of a name such as `defined(CONFIG_X)`
/// or `IS_ENABLED(CONFIG_X)` -- so that a `!` in front of it reverses the
/// whole of it.
pub fn is_atom(condition: &str) -> bool {
    let identifier = |text: &str| {
        !text.is_empty()
            && text.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !text.starts_with(|c: char| c.is_ascii_digit())
    };
    if let Some(name) = condition.strip_prefix("defined ") {
        return identifier(name.trim());
    }
    match condition.split_once('(') {
        Some((test, rest)) => {
            identifier(test)
                && rest
                    .strip_suffix(')')
                    .is_some_and(|name| identifier(name.trim()))
        }
        None => identifier(condition),
    }
}

/// Whether the text is one parenthesized group: it opens with `(` and that
/// parenthesis closes at the last character, not before. `(A) && (B)` opens
/// and closes with parentheses and is two groups.
///
/// Character constants are skipped, so `(A == '(') || (B == ')')` is two
/// groups; comments are gone before a condition is stored.
pub fn wholly_parenthesized(text: &str) -> bool {
    if !text.starts_with('(') {
        return false;
    }
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\'' => {
                at = char_constant_end(bytes, at);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth = match depth.checked_sub(1) {
                    Some(depth) => depth,
                    None => return false,
                };
                if depth == 0 {
                    return at + 1 == bytes.len();
                }
            }
            _ => {}
        }
        at += 1;
    }
    false
}

/// Where a character constant opened at `start` ends: past its closing
/// quote, reading `\'` and `\\` as escapes, or at the end of the text.
pub fn char_constant_end(bytes: &[u8], start: usize) -> usize {
    let mut at = start + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at += 2,
            b'\'' => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len().min(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_term_and_its_negation_round_trip() {
        for term in [
            "CONFIG_X",
            "defined(CONFIG_X)",
            "(A || B)",
            "!(A) && (B)",
            "('(' == 40 || A)",
        ] {
            let conjunct = as_conjunct(term);
            assert_eq!(negate_term(&negate_term(&conjunct)), conjunct, "{term}");
        }
        assert_eq!(negate_term("defined(X)"), "!defined(X)");
        assert_eq!(negate_term("!defined(X)"), "defined(X)");
        assert_eq!(negate_term("(A || B)"), "!(A || B)");
        assert_eq!(negate_term("!(A || B)"), "(A || B)");
        // Two groups behind one `!` are not one negated group.
        assert_eq!(as_conjunct("!(A) && (B)"), "(!(A) && (B))");
        assert_eq!(negate_term("(!(A) && (B))"), "!(!(A) && (B))");
    }

    #[test]
    fn only_kconfig_terms_are_facts_and_compounds_stay_whole() {
        assert_eq!(
            config_facts(
                "defined(CONFIG_A) && !defined(DEBUG) && (CONFIG_B || CONFIG_C) && !CONFIG_D \
                 && (defined(CONFIG_E) && IS_ENABLED(CONFIG_F)) && !defined CONFIG_G \
                 && (CONFIG_H || CONFIG_I && CONFIG_J)"
            ),
            vec![
                "defined(CONFIG_A)",
                "!CONFIG_D",
                "defined(CONFIG_E)",
                "IS_ENABLED(CONFIG_F)",
                "!defined(CONFIG_G)",
            ]
        );
        let facts = ["defined(CONFIG_A)", "!CONFIG_D", "IS_ENABLED(CONFIG_F)"];
        assert_eq!(
            contradiction(&facts, "X && !defined(CONFIG_A)"),
            Some("defined(CONFIG_A)")
        );
        assert_eq!(
            contradiction(&facts, "!defined CONFIG_A"),
            Some("defined(CONFIG_A)")
        );
        assert_eq!(contradiction(&facts, "CONFIG_D"), Some("!CONFIG_D"));
        assert_eq!(
            contradiction(&facts, "!IS_ENABLED(CONFIG_F)"),
            Some("IS_ENABLED(CONFIG_F)")
        );
        // A disjunction is never split, so it never contradicts.
        assert_eq!(
            contradiction(&facts, "(!defined(CONFIG_A) || CONFIG_E)"),
            None
        );
        // A macro other than a Kconfig symbol proves nothing across a call.
        assert_eq!(contradiction(&["defined(DEBUG)"], "!defined(DEBUG)"), None);
    }

    #[test]
    fn a_one_argument_test_of_a_name_is_an_atom() {
        assert!(is_atom("IS_ENABLED(CONFIG_PRINTK)"));
        assert!(is_atom("defined CONFIG_X"));
        assert!(!is_atom("IS_ENABLED(CONFIG_A) && B"));
        assert!(!is_atom("FOO(1, 2)"));
        assert_eq!(
            negate_term("IS_ENABLED(CONFIG_PRINTK)"),
            "!IS_ENABLED(CONFIG_PRINTK)"
        );
    }

    #[test]
    fn terms_split_only_at_the_top() {
        assert_eq!(
            terms("(A || B) && !(C && D) && defined(E) && ('&' == F)"),
            vec!["(A || B)", "!(C && D)", "defined(E)", "('&' == F)"]
        );
    }

    #[test]
    fn arms_of_one_if_exclude_each_other_and_independent_ifs_do_not() {
        // `#if A` / `#elif B` / `#else`, nested under `#if X`.
        let first = "X && A";
        let second = "X && !A && B";
        let third = "X && !A && !B";
        assert!(excludes(first, second));
        assert!(excludes(second, third));
        assert!(excludes(first, third));
        // `#if A` ... `#endif` then `#if B` ... `#endif`: both can hold.
        assert!(!excludes("A", "B"));
        // Nor does the shared outer arm separate anything.
        assert!(!excludes("X && A", "X"));
    }
}
