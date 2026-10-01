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

/// Whether a condition is one conjunct already: a name, a negated name, a
/// whole group, or a negated whole group.
fn is_term(condition: &str) -> bool {
    let positive = condition.strip_prefix('!').unwrap_or(condition);
    is_atom(positive) || wholly_parenthesized(positive)
}

/// Whether a condition is one name -- `defined(CONFIG_X)` or a bare
/// `CONFIG_X` -- so that a `!` in front of it reverses the whole of it.
pub fn is_atom(condition: &str) -> bool {
    let name = condition
        .strip_prefix("defined(")
        .and_then(|rest| rest.strip_suffix(')'))
        .or_else(|| condition.strip_prefix("defined "))
        .unwrap_or(condition);
    !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
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
