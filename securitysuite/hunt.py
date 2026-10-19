"""A small query language for hunting across findings.

The dashboard's search box does a substring match over the whole JSON blob of
an event. That finds things, but it cannot express the questions an analyst
actually asks - "critical detections that aren't resolved, on PowerShell
techniques, excluding the samples folder" - and a substring match on
``critical`` also hits a file literally named ``critical_report.txt``.

Grammar, smallest thing that answers those questions:

    query   := or
    or      := and ( ("OR" | "|") and )*
    and     := not ( ("AND" | "&")? not )*        # adjacency implies AND
    not     := ("NOT" | "-")? primary
    primary := "(" or ")" | term
    term    := [field ":"] value                  # bare value = free text

Fields: severity, status, type, rule, namespace, tag, file, path, sha256,
technique/attack, tactic, note. Values support ``*`` and ``?`` wildcards, and
may be quoted to include spaces. Unknown fields are a parse error rather than a
silent no-match, because a typo that quietly returns nothing is worse than one
that says so.

Evaluation runs against the event dicts the store already holds, so hunting
needs no separate index and stays consistent with what the dashboard shows.
"""
from __future__ import annotations

import fnmatch
import re

# field -> how to pull comparable strings out of an event
FIELDS = (
    "severity", "status", "type", "rule", "namespace", "tag", "file", "path",
    "sha256", "technique", "attack", "tactic", "note", "text",
)

_TOKEN = re.compile(r'''
    \s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<op>\bAND\b|\bOR\b|\bNOT\b|&&|\|\||&|\||(?<![\w*?])-(?=\S))
      | (?P<term>(?:[A-Za-z_]+:)?(?:"[^"]*"|'[^']*'|[^\s()]+))
    )''', re.VERBOSE | re.IGNORECASE)


class QueryError(ValueError):
    """The query could not be parsed; the message is shown to the operator."""


# ------------------------------------------------------------------ tokenize
def tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        match = _TOKEN.match(text, pos)
        if not match or match.end() == pos:
            raise QueryError("cannot parse from: " + text[pos:pos + 20])
        pos = match.end()
        if match.group("lparen"):
            tokens.append(("lparen", "("))
        elif match.group("rparen"):
            tokens.append(("rparen", ")"))
        elif match.group("op"):
            raw = match.group("op").upper()
            name = ("AND" if raw in ("AND", "&&", "&")
                    else "OR" if raw in ("OR", "||", "|") else "NOT")
            tokens.append(("op", name))
        else:
            tokens.append(("term", match.group("term")))
    return tokens


# --------------------------------------------------------------------- parse
class Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def parse(self) -> dict:
        node = self.parse_or()
        if self.pos != len(self.tokens):
            raise QueryError("unexpected " + str(self.peek()[1]))
        return node

    def parse_or(self) -> dict:
        node = self.parse_and()
        while self.peek() == ("op", "OR"):
            self.pos += 1
            node = {"op": "or", "left": node, "right": self.parse_and()}
        return node

    def parse_and(self) -> dict:
        node = self.parse_not()
        while True:
            kind, value = self.peek()
            if kind == "op" and value == "AND":
                self.pos += 1
            elif kind in ("term", "lparen") or (kind == "op" and value == "NOT"):
                pass                      # adjacency implies AND
            else:
                break
            node = {"op": "and", "left": node, "right": self.parse_not()}
        return node

    def parse_not(self) -> dict:
        if self.peek() == ("op", "NOT"):
            self.pos += 1
            return {"op": "not", "child": self.parse_not()}
        return self.parse_primary()

    def parse_primary(self) -> dict:
        kind, value = self.peek()
        if kind == "lparen":
            self.pos += 1
            node = self.parse_or()
            if self.peek()[0] != "rparen":
                raise QueryError("unclosed (")
            self.pos += 1
            return node
        if kind != "term":
            raise QueryError("expected a term, got " + str(value or "end of query"))
        self.pos += 1
        return make_term(value)


def make_term(raw: str) -> dict:
    field, _, value = raw.partition(":")
    if not _:
        field, value = "text", raw
    field = field.lower()
    if field not in FIELDS:
        raise QueryError(
            "unknown field '%s' - try: %s" % (field, ", ".join(sorted(FIELDS))))
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not value:
        raise QueryError("empty value for field '%s'" % field)
    return {"op": "term", "field": field, "value": value.lower()}


def parse(text: str) -> dict | None:
    """Parse a query, or None when it is blank (meaning: match everything)."""
    tokens = tokenize(text or "")
    if not tokens:
        return None
    return Parser(tokens).parse()


# ---------------------------------------------------------------- evaluation
def _values(event: dict, field: str) -> list[str]:
    """Comparable strings for one field of one event."""
    matches = event.get("matches") or []
    if field == "severity":
        return [str(event.get("severity") or "")]
    if field == "status":
        return [str(event.get("status") or "new")]
    if field == "type":
        return [str(event.get("event_type") or "")]
    if field == "rule":
        return [str(m.get("rule") or "") for m in matches]
    if field == "namespace":
        return [str(m.get("namespace") or "") for m in matches]
    if field == "tag":
        return [str(t) for m in matches for t in (m.get("tags") or [])]
    if field in ("file", "path"):
        out = [str(event.get("file_path") or ""), str(event.get("file_name") or "")]
        return [v for v in out if v]
    if field == "sha256":
        return [str(event.get("sha256") or "")]
    if field in ("technique", "attack"):
        return [str(t.get("id") or "")
                for m in matches for t in (m.get("attack") or [])]
    if field == "tactic":
        return [str(tactic) for m in matches
                for t in (m.get("attack") or []) for tactic in (t.get("tactics") or [])]
    if field == "note":
        return [str(event.get("triage_note") or "")]
    return []


def _matches_value(candidates: list[str], needle: str) -> bool:
    for candidate in candidates:
        low = candidate.lower()
        if "*" in needle or "?" in needle:
            if fnmatch.fnmatch(low, needle):
                return True
        elif needle in low:
            return True
    return False


def evaluate(node: dict | None, event: dict, blob: str) -> bool:
    if node is None:
        return True
    op = node["op"]
    if op == "and":
        return (evaluate(node["left"], event, blob)
                and evaluate(node["right"], event, blob))
    if op == "or":
        return (evaluate(node["left"], event, blob)
                or evaluate(node["right"], event, blob))
    if op == "not":
        return not evaluate(node["child"], event, blob)
    field, value = node["field"], node["value"]
    if field == "text":
        # Free text keeps the old whole-event substring behaviour, so a bare
        # word in the box still works the way operators expect.
        if "*" in value or "?" in value:
            return fnmatch.fnmatch(blob, "*" + value + "*")
        return value in blob
    return _matches_value(_values(event, field), value)


def run(query: str, events: list[dict], limit: int = 300) -> dict:
    """Filter events by query. Returns results plus what was understood."""
    try:
        tree = parse(query)
    except QueryError as exc:
        return {"error": str(exc), "query": query, "findings": [], "matched": 0}

    out: list[dict] = []
    scanned = 0
    for event in events:
        scanned += 1
        # The blob is only built for free-text terms, which is the expensive
        # case; field terms never pay for it.
        blob = ""
        if tree is not None and _needs_text(tree):
            blob = _blob(event)
        if evaluate(tree, event, blob):
            out.append(event)
            if len(out) >= limit:
                break
    return {
        "findings": out,
        "matched": len(out),
        "scanned": scanned,
        "query": query,
        "fields": sorted(FIELDS),
    }


def _needs_text(node: dict) -> bool:
    if node["op"] == "term":
        return node["field"] == "text"
    if node["op"] == "not":
        return _needs_text(node["child"])
    return _needs_text(node["left"]) or _needs_text(node["right"])


def _blob(event: dict) -> str:
    import json
    return json.dumps(event, default=str).lower()
