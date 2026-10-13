"""Minimal Sigma rule engine (supports the common subset used in this project).

Supported:
  - selections as dict (AND) or list of dicts (OR)
  - field modifiers: contains, startswith, endswith, re, all
  - condition: and / or / not / ( ) / "1 of sel*" / "all of sel*" / "1 of them" / "all of them"
"""
import fnmatch
import re
from pathlib import Path

import yaml


def load_rules(rules_dir):
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        with open(path, encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        rule["_file"] = path.name
        rules.append(rule)
    return rules


def _match_one(event_value, modifier, pattern):
    if event_value is None:
        return False
    ev = str(event_value).lower()
    pat = str(pattern).lower()
    if modifier == "contains":
        return pat in ev
    if modifier == "startswith":
        return ev.startswith(pat)
    if modifier == "endswith":
        return ev.endswith(pat)
    if modifier == "re":
        return re.search(str(pattern), str(event_value), re.IGNORECASE) is not None
    return ev == pat  # exact (case-insensitive)


def _match_field(event, key, expected):
    parts = key.split("|")
    field, mods = parts[0], parts[1:]
    require_all = "all" in mods
    mod = next((m for m in mods if m in ("contains", "startswith", "endswith", "re")), None)
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_one(event.get(field), mod, v) for v in values]
    return all(results) if require_all else any(results)


def _match_selection(event, selection):
    if isinstance(selection, list):  # list of dicts => OR
        return any(_match_selection(event, s) for s in selection)
    return all(_match_field(event, k, v) for k, v in selection.items())


class _Condition:
    def __init__(self, text, results):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos = 0
        self.results = results

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self):
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self):
        value = self._or()
        return value

    def _or(self):
        value = self._and()
        while self._peek() and self._peek().lower() == "or":
            self._next()
            rhs = self._and()
            value = value or rhs
        return value

    def _and(self):
        value = self._not()
        while self._peek() and self._peek().lower() == "and":
            self._next()
            rhs = self._not()
            value = value and rhs
        return value

    def _not(self):
        if self._peek() and self._peek().lower() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self):
        tok = self._next()
        if tok == "(":
            value = self._or()
            self._next()  # ')'
            return value
        if self._peek() == "of":  # "1 of x*" / "all of x*"
            quant = tok.lower()
            self._next()
            pattern = self._next()
            names = (list(self.results) if pattern == "them"
                     else [n for n in self.results if fnmatch.fnmatch(n, pattern)])
            vals = [self.results[n] for n in names]
            if not vals:
                return False
            return all(vals) if quant == "all" else any(vals)
        return self.results.get(tok, False)


def evaluate(rule, event):
    """Return True if the event matches the Sigma rule."""
    detection = rule["detection"]
    results = {name: _match_selection(event, sel)
               for name, sel in detection.items() if name != "condition"}
    return _Condition(detection["condition"], results).parse()


def run_detections(rules, events):
    alerts = []
    for event in events:
        for rule in rules:
            if evaluate(rule, event):
                alerts.append({
                    "time": event.get("UtcTime"),
                    "host": event.get("Computer"),
                    "user": event.get("User"),
                    "rule_id": rule["id"],
                    "rule_title": rule["title"],
                    "level": rule.get("level", "medium"),
                    "techniques": technique_ids(rule),
                    "tactics": tactic_names(rule),
                    "event_id": event.get("EventID"),
                    "image": event.get("Image"),
                    "command_line": event.get("CommandLine"),
                    "expected": event.get("_expected"),  # ground truth for validation
                })
    return alerts


def technique_ids(rule):
    return [t.split(".", 1)[1].upper() for t in rule.get("tags", [])
            if re.match(r"attack\.t\d{4}", t)]


def tactic_names(rule):
    return [t.split(".", 1)[1] for t in rule.get("tags", [])
            if t.startswith("attack.") and not re.match(r"attack\.t\d{4}", t)]
