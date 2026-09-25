"""Suspicious-UA signatures and the PAN-OS-style structured search
language (tokenizer, recursive-descent parser, AST evaluator, AST
editing helpers used by the metric tiles, and apply_search_query()).

Pure Python + pandas - no Streamlit - so it's importable and testable on
its own. Moved verbatim out of dashboard.py."""
import ipaddress
import json
import re


# Every pattern here must stay valid in BOTH Python's and JavaScript's
# regex dialects: the same list also drives the AG Grid table's red
# suspicious-row highlight (browser-side JS), via SUSPICIOUS_JS_REGEX_SOURCE.
SUSPICIOUS_PATTERNS = [
    r"curl", r"wget", r"nmap", r"zgrab", r"masscan", r"nikto", r"sqlmap",
    r"python-requests", r"urllib", r"go-http-client", r"aiohttp", r"java/",
    r"\$\{jndi:", r"\(\)\s*\{", r"select.*from", r"union.*select",
]
SUSPICIOUS_REGEX = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

# A JS string literal (JSON-encoded, so backslashes/quotes are escaped
# correctly) holding the same alternation, for `new RegExp(<this>, 'i')`.
SUSPICIOUS_JS_REGEX_SOURCE = json.dumps("|".join(SUSPICIOUS_PATTERNS))


# -----------------------------------------------------------------------------
# PAN-OS-STYLE STRUCTURED SEARCH
# -----------------------------------------------------------------------------
# A small query language for the search box, modeled on PAN-OS's own log
# filter syntax (https://docs.paloaltonetworks.com/ngfw/administration/
# monitoring/use-syslog-for-monitoring/syslog-field-descriptions/
# url-filtering-log-fields), e.g. (user_agent contains 'Moz') or
# (addr.src in 10.0.0.0/8), with arbitrary paren nesting for grouping, e.g.
# ((addr in 10.0.0.0/8) or (addr in 172.25.0.0/16)) and (url contains 'Moz').
# Only fields that actually map to a table column are supported - First
# Seen, Last Seen, Direction, and Hit Count are deliberately left out, since
# sorting, the filter tiles, and the grid's own numeric column filter
# already cover those.
#
# Values can be quoted ('Mozilla/5.0') or bare (claude, 10.200.36.70,
# curl/8.0, 013101001234) - quotes are only required when a value contains
# whitespace or parentheses, starts with ' or !, or is itself one of the
# connectors and/or/not, since those would otherwise tokenize as something
# other than a plain value.
#
# A query can also mix structured syntax with trailing free text, e.g.
# (user_agent contains 'Mozilla') 10.200.36.70 - the structured part is
# parsed normally, and anything left over is ANDed in as an ordinary
# substring match across every column (the same behavior plain search has
# always had). See parse_pan_style_query()'s docstring for exactly how that
# split is decided.
#
# Plain text with no recognized structure at all (e.g. just "curl") falls
# back entirely to the existing search-every-column substring match - see
# apply_search_query() below.
SEARCH_FIELD_MAP = {
    "user_agent": ("User-Agent", "text"),
    "url": ("Last URL", "text"),
    "action": ("Last Action", "text"),
    "addr.src": ("Last Src IP", "ip"),
    "addr.dst": ("Last Dst IP", "ip"),
    # PAN-OS's own "addr" (no .src/.dst suffix) matches either direction -
    # "any ip from source or dest in this subnet."
    "addr": (("Last Src IP", "Last Dst IP"), "ip_either"),
    "device": ("Device Name", "text"),
    "device.serial": ("Device Serial", "text"),
}
SEARCH_OPS_BY_KIND = {
    "text": {"eq", "neq", "contains"},
    "ip": {"eq", "neq", "in"},
    "ip_either": {"eq", "neq", "in"},
}

# Standalone predicate keywords - "(suspicious)", "(egress)", "(ingress)" -
# are complete clauses with no operator or value, unlike every other field
# in SEARCH_FIELD_MAP. These are what let the metric tiles and the search
# box be two views of the same state: a tile click edits the query text to
# add/remove one of these; the query text (re-parsed) is what decides
# whether a tile shows as pressed. They only take on this special meaning
# where a field name is expected (the start of a clause) - "user_agent eq
# suspicious" still works fine, matching a UA that literally contains the
# word "suspicious", since that's a bare WORD in value position, not field
# position.
PREDICATE_KEYWORDS = {"suspicious", "egress", "ingress"}

_QUERY_TOKEN_RE = re.compile(r"""
    (?P<LPAREN>\()
  | (?P<RPAREN>\))
  | (?P<BANG>!)
  | (?P<STRING>'(?:[^'\\]|\\.)*')
  # Any other run of characters up to whitespace or a paren is one token,
  # classified by _tokenize_query() as CIDR, WORD (field names, keywords,
  # simple bare values), or BARE (anything else - curl/8.0, 013101001234,
  # fw-branch, 10.1.2). A run can't START with ' or ! (those begin a quoted
  # string or a negation), but may contain them later (it's, x!y).
  | (?P<RUN>[^\s()'!][^\s()]*)
""", re.VERBOSE)
_CIDR_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")


def _tokenize_query(text):
    """Each token carries its (start, end) character offsets in the
    original string, alongside its kind and text - used by
    parse_pan_style_query() to recover the exact leftover substring when a
    query mixes structured syntax with trailing free text."""
    tokens = []
    pos = 0
    length = len(text)
    while pos < length:
        if text[pos].isspace():
            pos += 1
            continue
        m = _QUERY_TOKEN_RE.match(text, pos)
        if not m:
            raise ValueError(f"unexpected character at position {pos}")
        start = pos
        pos = m.end()
        kind = m.lastgroup
        matched = m.group(kind)
        if kind == "RUN":
            # Before BARE existed, anything that wasn't CIDR- or WORD-shaped
            # made this function raise, which failed the WHOLE query - so a
            # bare all-digit serial (device.serial eq 013101001234), or
            # trailing free text like "(egress) fw-branch", silently fell
            # back to a literal search for the entire string and matched
            # nothing.
            if _CIDR_RE.fullmatch(matched):
                kind = "CIDR"
            elif _WORD_RE.fullmatch(matched):
                kind = "WORD"
            else:
                kind = "BARE"
        if kind == "STRING":
            tokens.append(("STRING", matched[1:-1].replace("\\'", "'").replace("\\\\", "\\"), start, pos))
        elif kind == "WORD":
            lowered = matched.lower()
            if lowered == "and":
                tokens.append(("AND", matched, start, pos))
            elif lowered == "or":
                tokens.append(("OR", matched, start, pos))
            elif lowered == "not":
                tokens.append(("NOT", matched, start, pos))
            else:
                tokens.append(("WORD", matched, start, pos))
        else:
            tokens.append((kind, matched, start, pos))
    return tokens


def parse_pan_style_query(query_text):
    """Parses as much valid structured syntax as possible starting from the
    beginning of query_text, and returns one of three outcomes:

      - (ast, True, None): the whole string parsed as a structured query.
      - (ast, True, leftover_text): a structured PREFIX parsed cleanly, and
        what follows it doesn't look like a broken continuation of the
        boolean expression (it doesn't start with another and/or/not or a
        stray closing paren - those would suggest a typo, not intentional
        trailing text). leftover_text is the exact trailing substring, to
        be ANDed in by the caller as a plain search-every-column match.
      - (None, False, None): parsing failed outright (an unrecognized
        field, a bad operator for that field's type, unbalanced parens, a
        genuinely broken continuation, or the string not starting with
        valid structured syntax at all) - the caller falls back to a full
        plain-text search across all columns, rather than showing a syntax
        error. That's deliberate: this reruns on every autorefresh tick,
        and a query is often typed one character at a time, so treating a
        not-yet-valid partial query as an error would flash red on every
        keystroke instead of just quietly not matching yet.
    """
    try:
        tokens = _tokenize_query(query_text)
    except ValueError:
        return None, False, None
    if not tokens:
        return None, False, None

    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def advance():
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def parse_or():
        node = parse_and()
        while peek() and peek()[0] == "OR":
            advance()
            node = ("or", node, parse_and())
        return node

    def parse_and():
        node = parse_unary()
        while peek() and peek()[0] == "AND":
            advance()
            node = ("and", node, parse_unary())
        return node

    def parse_unary():
        # "!" is accepted as a direct equivalent to "not", per PAN-OS
        # convention - !(user_agent eq 'Mozilla') is the same as
        # not (user_agent eq 'Mozilla'), or user_agent neq 'Mozilla'.
        if peek() and peek()[0] in ("NOT", "BANG"):
            advance()
            return ("not", parse_unary())
        return parse_primary()

    def parse_primary():
        tok = peek()
        if tok is None:
            raise ValueError("unexpected end of query")
        if tok[0] == "LPAREN":
            advance()
            node = parse_or()
            if not (peek() and peek()[0] == "RPAREN"):
                raise ValueError("expected closing )")
            advance()
            return node
        if tok[0] == "WORD" and tok[1].lower() in PREDICATE_KEYWORDS:
            advance()
            return ("predicate", tok[1].lower())
        return parse_comparison()

    def parse_comparison():
        field_tok = advance()
        if field_tok[0] != "WORD":
            raise ValueError("expected a field name")
        field = field_tok[1].lower()
        if field not in SEARCH_FIELD_MAP:
            raise ValueError(f"unknown field: {field}")
        _, kind = SEARCH_FIELD_MAP[field]

        op_tok = advance()
        if op_tok[0] != "WORD":
            raise ValueError("expected an operator")
        op = op_tok[1].lower()
        if op not in SEARCH_OPS_BY_KIND[kind]:
            raise ValueError(f"operator {op!r} isn't valid for {field}")

        # STRING (quoted) or any bare token (WORD/CIDR/BARE) is a valid
        # value - quoting is only actually required for a value containing
        # whitespace or parentheses, starting with ' or !, or colliding
        # with a reserved word (and/or/not tokenize as connectors).
        value_tok = advance()
        if value_tok[0] in ("STRING", "CIDR", "WORD", "BARE"):
            value = value_tok[1]
        else:
            raise ValueError("expected a value")
        return ("cmp", field, op, value)

    try:
        ast = parse_or()
    except (ValueError, IndexError):
        return None, False, None

    if pos[0] == len(tokens):
        return ast, True, None

    leftover_tok = tokens[pos[0]]
    if leftover_tok[0] in ("AND", "OR", "NOT", "RPAREN"):
        # Looks like the boolean expression was meant to continue (another
        # connector, or an extra closing paren) but doesn't validly - more
        # likely a typo in an otherwise-structured query than intentional
        # trailing text, so don't guess: fall back completely.
        return None, False, None

    leftover_text = query_text[leftover_tok[2]:].strip()
    if not leftover_text:
        return ast, True, None
    return ast, True, leftover_text


def _eval_text_cmp(cell_value, op, value):
    cell = str(cell_value or "").casefold()
    target = str(value).casefold()
    if op == "eq":
        return cell == target
    if op == "neq":
        return cell != target
    if op == "contains":
        return target in cell
    return False


def _eval_ip_cmp(cell_value, op, value):
    try:
        cell_ip = ipaddress.ip_address(str(cell_value or "").strip())
    except ValueError:
        return False
    if op == "in":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return cell_ip in network
    try:
        target_ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if op == "eq":
        return cell_ip == target_ip
    if op == "neq":
        return cell_ip != target_ip
    return False


def eval_query_ast(node, row):
    kind = node[0]
    if kind == "or":
        return eval_query_ast(node[1], row) or eval_query_ast(node[2], row)
    if kind == "and":
        return eval_query_ast(node[1], row) and eval_query_ast(node[2], row)
    if kind == "not":
        return not eval_query_ast(node[1], row)
    if kind == "predicate":
        pred = node[1]
        if pred == "suspicious":
            return bool(SUSPICIOUS_REGEX.search(str(row.get("User-Agent", "") or "")))
        if pred == "egress":
            return str(row.get("Direction", "")) == "egress"
        if pred == "ingress":
            return str(row.get("Direction", "")) == "ingress"
        return False
    # kind == "cmp"
    _, field, op, value = node
    column, field_kind = SEARCH_FIELD_MAP[field]
    if field_kind == "ip_either":
        src_col, dst_col = column
        return (
            _eval_ip_cmp(row.get(src_col), op, value)
            or _eval_ip_cmp(row.get(dst_col), op, value)
        )
    cell_value = row.get(column)
    if field_kind == "ip":
        return _eval_ip_cmp(cell_value, op, value)
    return _eval_text_cmp(cell_value, op, value)


def ast_contains_predicate(node, name):
    """Walks the tree checking for a ("predicate", name) node anywhere -
    used to derive a tile's pressed state from the current query text. Note
    this checks presence anywhere in the tree, not logical guarantee: a
    hand-written "(suspicious) or (egress)" would show the Suspicious tile
    as pressed even though a row could match via the OR without actually
    being suspicious. Real logical analysis to avoid that edge case isn't
    worth the complexity for queries built by hand-editing rather than
    clicking tiles."""
    if node is None:
        return False
    kind = node[0]
    if kind == "predicate":
        return node[1] == name
    if kind == "not":
        return ast_contains_predicate(node[1], name)
    if kind in ("and", "or"):
        return ast_contains_predicate(node[1], name) or ast_contains_predicate(node[2], name)
    return False


def ast_strip_predicate(node, name):
    """Returns a new AST with every ("predicate", name) node removed,
    collapsing and/or nodes whose branch disappears. Returns None if the
    whole tree was removed (e.g. the tree was just that one predicate)."""
    if node is None:
        return None
    kind = node[0]
    if kind == "predicate":
        return None if node[1] == name else node
    if kind == "not":
        inner = ast_strip_predicate(node[1], name)
        return None if inner is None else ("not", inner)
    if kind in ("and", "or"):
        left = ast_strip_predicate(node[1], name)
        right = ast_strip_predicate(node[2], name)
        if left is None and right is None:
            return None
        if left is None:
            return right
        if right is None:
            return left
        return (kind, left, right)
    # kind == "cmp" - never contains a nested predicate
    return node


def ast_add_predicate(node, name):
    """ANDs a new ("predicate", name) node onto the existing tree (or
    returns just the predicate alone if the tree was empty)."""
    new_node = ("predicate", name)
    if node is None:
        return new_node
    return ("and", node, new_node)


def _format_query_value(value):
    """Values are always emitted quoted when regenerating query text from an
    AST (as opposed to what a human typed, where bare values are also
    valid) - simplest way to guarantee round-tripping safely regardless of
    whether the value happens to collide with a reserved word or contain
    punctuation that isn't valid in a bare token."""
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def ast_to_query_text(node):
    """Serializes an AST back into query syntax. and/or results are always
    wrapped in an extra pair of parens, even though a flat hand-typed chain
    like "(a) and (b) and (c)" doesn't strictly need them - this guarantees
    correct precedence round-tripping in every case (in particular, an "or"
    nested inside an "and", or either nested under a "not") without needing
    to reason case-by-case about when it's actually safe to omit them. The
    parser already accepts arbitrarily nested/redundant parens without
    complaint, so the extra verbosity costs nothing functionally - it just
    means a query gets more heavily parenthesized after a tile edits it,
    which is a style this query language treats as normal anyway."""
    if node is None:
        return ""
    kind = node[0]
    if kind == "predicate":
        return f"({node[1]})"
    if kind == "cmp":
        _, field, op, value = node
        return f"({field} {op} {_format_query_value(value)})"
    if kind == "not":
        return f"!{ast_to_query_text(node[1])}"
    if kind == "and":
        return f"({ast_to_query_text(node[1])} and {ast_to_query_text(node[2])})"
    if kind == "or":
        return f"({ast_to_query_text(node[1])} or {ast_to_query_text(node[2])})"
    return ""


def apply_search_query(df, search_query):
    """Applies the search box's value to df: structured PAN-OS-style parsing
    when the query parses as one (optionally with a trailing plain-text
    clause ANDed in - see parse_pan_style_query()), falling back to the
    original plain substring-across-all-columns match otherwise."""
    ast, parsed_ok, leftover_text = parse_pan_style_query(search_query)
    if parsed_ok:
        mask = df.apply(lambda row: eval_query_ast(ast, row), axis=1)
        if leftover_text:
            leftover_cf = leftover_text.casefold()
            text_mask = df.astype(str).apply(
                lambda col: col.str.casefold().str.contains(leftover_cf, regex=False, na=False)
            ).any(axis=1)
            mask = mask & text_mask
        return df[mask], True
    query = str(search_query).casefold()
    mask = df.astype(str).apply(
        lambda col: col.str.casefold().str.contains(query, regex=False, na=False)
    ).any(axis=1)
    return df[mask], False
