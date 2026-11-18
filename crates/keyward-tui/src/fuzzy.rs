//! A small fzf-style fuzzy matcher.
//!
//! The query must appear in the text as a case-insensitive subsequence.
//! Matches score higher when they are contiguous, start a word, or start
//! the text, and lower when the matched characters are spread out.

/// Score `query` against `text`; `None` if it does not match.
/// An empty (or all-whitespace) query matches everything with score 0.
pub fn score(query: &str, text: &str) -> Option<i64> {
    let q: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if q.is_empty() {
        return Some(0);
    }
    let t: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();

    let mut total = 0i64;
    let mut qi = 0;
    let mut prev_match: Option<usize> = None;
    for (ti, &c) in t.iter().enumerate() {
        if qi == q.len() {
            break;
        }
        if c != q[qi] {
            continue;
        }
        total += 16;
        if ti == 0 {
            total += 15;
        }
        let word_start = ti == 0 || !t[ti - 1].is_alphanumeric();
        if word_start {
            total += 10;
        }
        match prev_match {
            Some(p) if p + 1 == ti => total += 12,
            Some(p) => total -= (ti - p - 1).min(10) as i64,
            None => total -= ti.min(10) as i64 / 2,
        }
        prev_match = Some(ti);
        qi += 1;
    }
    if qi < q.len() {
        return None;
    }
    // A literal substring is what people usually mean, especially when it
    // starts a word ("hub" in "GitHub" counts less than "Hub" in "Git Hub").
    let substring_at_word_start =
        (0..t.len()).any(|i| t[i..].starts_with(&q) && (i == 0 || !t[i - 1].is_alphanumeric()));
    if substring_at_word_start {
        total += 25;
    } else if t.windows(q.len()).any(|w| w == q.as_slice()) {
        total += 8;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsequence_required() {
        assert!(score("ghb", "GitHub").is_some());
        assert!(score("gth", "GitHub").is_some());
        assert!(score("hg", "GitHub").is_none());
        assert!(score("x", "GitHub").is_none());
    }

    #[test]
    fn empty_query_matches_all() {
        assert_eq!(score("", "anything"), Some(0));
        assert_eq!(score("   ", "anything"), Some(0));
    }

    #[test]
    fn case_and_spaces_are_ignored() {
        assert_eq!(score("GIT hub", "github"), score("github", "GitHub"));
    }

    #[test]
    fn ranking_prefers_prefix_contiguous_and_word_starts() {
        let s = |q, t| score(q, t).unwrap();
        assert!(s("git", "GitHub") > s("git", "Digital Gitea"));
        assert!(s("mail", "Mail") > s("mail", "My Account Internal Link"));
        assert!(s("gh", "Git Hub") > s("gh", "Laughing"));
        assert!(s("bank", "Bank") > s("bank", "Big Bank"));
    }

    #[test]
    fn unicode_does_not_panic() {
        assert!(score("zó", "Zółw Żółty").is_some());
        assert!(score("ß", "Straße").is_some());
    }
}
