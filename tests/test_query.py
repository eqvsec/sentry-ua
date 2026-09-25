"""sentry_ua.query: suspicious signatures and the PAN-OS-style search
language - parsing, fallback rules, evaluation, and the tile <-> query-text
AST editing round trip."""
import json
import re

import pandas as pd
import pytest

from sentry_ua import query as q


# --- suspicious signatures ------------------------------------------------------

@pytest.mark.parametrize(
    "ua",
    [
        "curl/8.4.0", "Wget/1.21", "Nmap Scripting Engine", "zgrab/0.x", "masscan/1.3",
        "Nikto/2.5", "sqlmap/1.8", "python-requests/2.32", "Python-urllib/3.12",
        "Go-http-client/1.1", "aiohttp/3.9", "Java/17.0.2", "${jndi:ldap://x/a}",
        "() { :; }; /bin/bash", "1 UNION ALL SELECT", "select name from users",
    ],
)
def test_suspicious_matches(ua):
    assert q.SUSPICIOUS_REGEX.search(ua)


@pytest.mark.parametrize(
    "ua",
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36",
        "Slack/4.39.95",
        "Microsoft Office/16.0",
        "okhttp/4.12.0",
    ],
)
def test_suspicious_does_not_match_normal_clients(ua):
    assert not q.SUSPICIOUS_REGEX.search(ua)


def test_js_regex_source_is_the_same_pattern_list():
    # The grid's red-row highlight is built from this; it must decode to
    # exactly the alternation the Python side uses.
    assert json.loads(q.SUSPICIOUS_JS_REGEX_SOURCE) == "|".join(q.SUSPICIOUS_PATTERNS)
    assert json.loads(q.SUSPICIOUS_JS_REGEX_SOURCE) == q.SUSPICIOUS_REGEX.pattern


def test_patterns_avoid_python_only_regex_syntax():
    # Anything here must also be valid JavaScript regex - no (?P<...>),
    # inline flags, \A/\Z, or possessive/atomic constructs.
    for pattern in q.SUSPICIOUS_PATTERNS:
        assert not re.search(r"\(\?[PaimsxL<#>]|\\[AZ]|\*\+|\+\+", pattern), pattern


# --- parser outcomes ------------------------------------------------------------

@pytest.mark.parametrize(
    "text, expected_ast",
    [
        ("user_agent eq curl", ("cmp", "user_agent", "eq", "curl")),
        ("(user_agent contains 'Mozilla/5.0')", ("cmp", "user_agent", "contains", "Mozilla/5.0")),
        ("addr.src in 10.0.0.0/8", ("cmp", "addr.src", "in", "10.0.0.0/8")),
        ("addr eq 10.200.36.70", ("cmp", "addr", "eq", "10.200.36.70")),
        ("(suspicious)", ("predicate", "suspicious")),
        ("EGRESS", ("predicate", "egress")),
        ("USER_AGENT EQ x", ("cmp", "user_agent", "eq", "x")),
        ("!(action eq 'allow')", ("not", ("cmp", "action", "eq", "allow"))),
        ("not (ingress)", ("not", ("predicate", "ingress"))),
        ("device contains branch", ("cmp", "device", "contains", "branch")),
        ("device.serial eq '0123'", ("cmp", "device.serial", "eq", "0123")),
        ("(url eq 'it\\'s')", ("cmp", "url", "eq", "it's")),
        ("user_agent eq suspicious", ("cmp", "user_agent", "eq", "suspicious")),
    ],
)
def test_parse_structured(text, expected_ast):
    assert q.parse_pan_style_query(text) == (expected_ast, True, None)


def test_and_binds_tighter_than_or():
    ast, ok, _ = q.parse_pan_style_query("(egress) or (ingress) and (suspicious)")
    assert ok
    assert ast == ("or", ("predicate", "egress"), ("and", ("predicate", "ingress"), ("predicate", "suspicious")))


def test_nested_readme_example():
    text = "((addr in 10.0.0.0/8) or (addr in 172.25.0.0/16)) and ((url contains 'Mozilla') or (url contains claude))"
    ast, ok, leftover = q.parse_pan_style_query(text)
    assert ok and leftover is None
    assert ast[0] == "and" and ast[1][0] == "or" and ast[2][0] == "or"


@pytest.mark.parametrize(
    "text, leftover",
    [
        ("(user_agent contains 'Mozilla') 10.200.36.70", "10.200.36.70"),
        ("(suspicious) curl", "curl"),
        ("(egress) some free text here", "some free text here"),
    ],
)
def test_hybrid_query_keeps_exact_trailing_text(text, leftover):
    ast, ok, rest = q.parse_pan_style_query(text)
    assert ok and ast is not None
    assert rest == leftover


@pytest.mark.parametrize(
    "text",
    [
        "",
        "curl",                      # plain text: WORD with no operator
        "(bogus eq 1)",              # unknown field
        "(addr contains 10)",        # operator not valid for an IP field
        "(user_agent in 10.0.0.0/8)",  # operator not valid for a text field
        "((egress)",                 # unbalanced
        "(egress) and",              # dangling connector
        "(egress) )",                # stray closing paren
        "(egress) or or (ingress)",
        "'unterminated",
        "user_agent eq",             # missing value
        "user_agent eq (x)",
        "@#$",                       # untokenizable
    ],
)
def test_parse_failures_fall_back(text):
    assert q.parse_pan_style_query(text) == (None, False, None)


# --- evaluation -----------------------------------------------------------------

@pytest.fixture
def df():
    return pd.DataFrame(
        [
            {"User-Agent": "curl/8.0", "Direction": "egress", "Last URL": "claude.ai/x",
             "Last Action": "alert", "Last Src IP": "10.1.2.3", "Last Dst IP": "8.8.8.8",
             "Device Name": "fw-branch-1", "Device Serial": "0123"},
            {"User-Agent": "Mozilla/5.0", "Direction": "ingress", "Last URL": "example.com",
             "Last Action": "block-url", "Last Src IP": "203.0.113.5", "Last Dst IP": "172.25.1.1",
             "Device Name": "fw-hq", "Device Serial": "999"},
            {"User-Agent": "Slack/4.0", "Direction": "egress", "Last URL": "",
             "Last Action": "allow", "Last Src IP": "", "Last Dst IP": "not-an-ip",
             "Device Name": "", "Device Serial": ""},
        ]
    )


def matched(df, text):
    result, _ = q.apply_search_query(df, text)
    return list(result["User-Agent"])


@pytest.mark.parametrize(
    "text, expected",
    [
        ("(suspicious)", ["curl/8.0"]),
        ("(egress)", ["curl/8.0", "Slack/4.0"]),
        ("(ingress)", ["Mozilla/5.0"]),
        ("!(egress)", ["Mozilla/5.0"]),
        ("user_agent eq 'CURL/8.0'", ["curl/8.0"]),        # case-insensitive eq
        ("user_agent neq 'curl/8.0'", ["Mozilla/5.0", "Slack/4.0"]),
        ("user_agent contains moz", ["Mozilla/5.0"]),
        ("addr.src in 10.0.0.0/8", ["curl/8.0"]),
        ("addr.dst in 172.16.0.0/12", ["Mozilla/5.0"]),
        ("addr in 8.8.8.0/24", ["curl/8.0"]),              # matches via dst
        ("addr in 203.0.113.0/24", ["Mozilla/5.0"]),       # matches via src
        ("addr eq 8.8.8.8", ["curl/8.0"]),
        ("addr.src neq 10.1.2.3", ["Mozilla/5.0"]),        # unparseable cells never match
        ("addr.src in not_a_cidr", []),
        ("device contains branch", ["curl/8.0"]),
        ("device.serial eq '999'", ["Mozilla/5.0"]),
        ("(egress) and (action eq allow)", ["Slack/4.0"]),
        ("(suspicious) or (ingress)", ["curl/8.0", "Mozilla/5.0"]),
        ("(egress) and (ingress)", []),                     # contradiction left as written
        ("(egress) slack", ["Slack/4.0"]),                  # hybrid: structured AND free text
        ("(egress) 10.1.2.3", ["curl/8.0"]),
    ],
)
def test_apply_structured_queries(df, text, expected):
    result, structured = q.apply_search_query(df, text)
    assert structured is True
    assert list(result["User-Agent"]) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("curl", ["curl/8.0"]),
        ("EXAMPLE.COM", ["Mozilla/5.0"]),
        ("fw-", ["curl/8.0", "Mozilla/5.0"]),
        (".*", []),                       # literal, never a regex
        ("(bogus eq 1)", []),             # failed parse -> literal substring
    ],
)
def test_apply_plain_text_fallback(df, text, expected):
    result, structured = q.apply_search_query(df, text)
    assert structured is False
    assert list(result["User-Agent"]) == expected


def test_apply_on_empty_frame():
    empty = pd.DataFrame(columns=["User-Agent", "Direction"])
    result, _ = q.apply_search_query(empty, "(egress)")
    assert result.empty


# --- AST editing (what the metric tiles do) -------------------------------------

ROUND_TRIP_QUERIES = [
    "(suspicious)",
    "(egress) and (suspicious)",
    "((addr in 10.0.0.0/8) or (addr in 172.25.0.0/16)) and ((url contains 'Mozilla') or (url contains claude))",
    "!(action eq 'allow') and addr.dst in 172.16.0.0/12",
    "not ((egress) or (ingress))",
    "(user_agent eq 'and')",                       # value colliding with a reserved word
    "(url eq 'it\\'s a \\\\ path')",               # quote + backslash escaping
    "(user_agent contains 'curl/8.0')",
]


@pytest.mark.parametrize("text", ROUND_TRIP_QUERIES)
def test_ast_to_query_text_round_trips(text):
    ast, ok, leftover = q.parse_pan_style_query(text)
    assert ok and leftover is None
    regenerated = q.ast_to_query_text(ast)
    assert q.parse_pan_style_query(regenerated) == (ast, True, None)
    # And regenerating again is stable.
    assert q.ast_to_query_text(q.parse_pan_style_query(regenerated)[0]) == regenerated


def test_ast_to_query_text_of_nothing():
    assert q.ast_to_query_text(None) == ""


def test_contains_predicate_anywhere_in_tree():
    ast, _, _ = q.parse_pan_style_query("(url contains x) and not ((suspicious) or (egress))")
    assert q.ast_contains_predicate(ast, "suspicious")
    assert q.ast_contains_predicate(ast, "egress")
    assert not q.ast_contains_predicate(ast, "ingress")
    assert not q.ast_contains_predicate(None, "egress")


def test_strip_predicate_collapses_branches():
    ast, _, _ = q.parse_pan_style_query("((egress) and (suspicious)) and (url contains x)")
    stripped = q.ast_strip_predicate(ast, "egress")
    assert stripped == ("and", ("predicate", "suspicious"), ("cmp", "url", "contains", "x"))
    assert q.ast_strip_predicate(("predicate", "egress"), "egress") is None
    assert q.ast_strip_predicate(("not", ("predicate", "egress")), "egress") is None
    assert q.ast_strip_predicate(None, "egress") is None


def test_add_predicate():
    assert q.ast_add_predicate(None, "egress") == ("predicate", "egress")
    base = ("cmp", "url", "contains", "x")
    assert q.ast_add_predicate(base, "suspicious") == ("and", base, ("predicate", "suspicious"))


def test_tile_toggle_sequence_matches_dashboard_behavior():
    """Mirrors dashboard.sync_query_predicate: toggle suspicious on, then
    egress, then ingress (mutually exclusive with egress), then suspicious
    off - checking the text a user would see in the search box each time."""

    def toggle(text, name, exclusive=()):
        ast = q.parse_pan_style_query(text)[0] if text else None
        if q.ast_contains_predicate(ast, name):
            ast = q.ast_strip_predicate(ast, name)
        else:
            for other in exclusive:
                ast = q.ast_strip_predicate(ast, other)
            ast = q.ast_add_predicate(ast, name)
        return q.ast_to_query_text(ast)

    text = toggle("", "suspicious")
    assert text == "(suspicious)"
    text = toggle(text, "egress", ("ingress",))
    assert text == "((suspicious) and (egress))"
    text = toggle(text, "ingress", ("egress",))
    assert text == "((suspicious) and (ingress))"
    text = toggle(text, "suspicious")
    assert text == "(ingress)"


# --- bare-token regressions ------------------------------------------------
# These were strict xfails until _tokenize_query() gained its catch-all BARE
# token: anything that wasn't CIDR- or WORD-shaped used to make the
# tokenizer raise, failing the WHOLE query into a literal substring search
# for the entire string - which matched nothing.

@pytest.mark.parametrize(
    "text, expected",
    [
        ("device.serial eq 0123", ["curl/8.0"]),             # PAN-OS serials are all digits
        ("device.serial eq 999", ["Mozilla/5.0"]),
        ("device.serial eq 013101001234", []),
        ("user_agent eq curl/8.0", ["curl/8.0"]),            # '/' no longer needs quoting
        ("user_agent contains 5.0", ["Mozilla/5.0"]),
        ("url eq claude.ai/x", ["curl/8.0"]),
        ("device eq fw-branch-1", ["curl/8.0"]),
        ("action eq block-url", ["Mozilla/5.0"]),
    ],
)
def test_bare_values_with_digits_and_punctuation(df, text, expected):
    result, structured = q.apply_search_query(df, text)
    assert structured is True
    assert list(result["User-Agent"]) == expected


@pytest.mark.parametrize(
    "text, leftover, expected",
    [
        ("(egress) fw-branch", "fw-branch", ["curl/8.0"]),
        ("(egress) 10.1.2", "10.1.2", ["curl/8.0"]),
        ("(suspicious) curl/8", "curl/8", ["curl/8.0"]),
        ("(egress) it's", "it's", []),
        ("(ingress) a b/c", "a b/c", []),
    ],
)
def test_hybrid_trailing_text_with_punctuation(df, text, leftover, expected):
    assert q.parse_pan_style_query(text)[2] == leftover
    assert matched(df, text) == expected


def test_clicking_a_tile_with_punctuated_free_text_typed(df):
    """What dashboard.sync_query_predicate produces when Suspicious is
    clicked with "curl/8" already typed: "(suspicious) curl/8" - which used
    to fail to parse, emptying the table instead of showing curl."""
    assert matched(df, "curl/8") == ["curl/8.0"]
    assert matched(df, "(suspicious) curl/8") == ["curl/8.0"]


@pytest.mark.parametrize(
    "text",
    [
        "curl/8",                     # plain text: a BARE token can't be a field name
        "1.2.3.4 eq x",               # ...nor can a CIDR
        "user_agent eq and",          # connectors still need quoting
        "user_agent eq (x)",          # parens still need quoting
        "addr.src in 10.0.0.0/8)",    # stray paren is still a broken query, not free text
        "'unterminated",
    ],
)
def test_bare_token_does_not_loosen_the_real_failure_cases(text):
    assert q.parse_pan_style_query(text) == (None, False, None)


def test_bare_token_offsets_cover_the_original_text():
    tokens = q._tokenize_query("(egress) fw-branch/1 x")
    assert [(t[0], t[1]) for t in tokens] == [
        ("LPAREN", "("), ("WORD", "egress"), ("RPAREN", ")"), ("BARE", "fw-branch/1"), ("WORD", "x"),
    ]
    text = "(egress) fw-branch/1 x"
    assert all(text[start:end] == value for _, value, start, end in tokens)
