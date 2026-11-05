"""Inventory every notification call site and assert the rendered text rules.

The product tree is read as text and with `ast`; no server, browser or vault runs
here, so the module stays fast. A new notification call site, a removed one, or a
reworded literal fails until the table below is updated - that is the point: the
rendered text may not change unnoticed.

A CLI notification is posted by `_trigger`, which renders
``"**<caller>**: " + message``. `Row.text` is the message after that prefix; the
prefix itself is checked once against the `_trigger` payload. Page notifications
are emitted directly by `Notification.emit`, so `Row.text` is their whole text.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CLI = "jupyterlab_passkey_extension/cli.py"
VCLI = "jupyterlab_passkey_extension/vault/cli.py"
VCLIENT = "jupyterlab_passkey_extension/vault/client.py"
COPY_TS = "src/copy.ts"
SHOW_TS = "src/show.ts"
PLUGIN_TS = "src/vault/plugin.ts"

# The exact number of notification call sites in the product tree: 8 Python calls
# (cli.py 4, vault/cli.py 2, vault/client.py 2) and 4 page calls. The unlock toast is
# raised through the notifications ingest; its local Notification.emit is the fallback
# and the one page site the scan sees for it. Each site appears once in SITES. New
# notification: add its site and its row(s) here and raise this number; the inventory
# test names the `file:line` that has no row.
EXPECTED_CALL_SITES = 12

# The number of rendered texts. A ternary branch or a helper caller contributes a
# row of its own, so a dropped row is a text no longer checked. New notification:
# add its row and raise this number with EXPECTED_CALL_SITES.
EXPECTED_ROWS = 28

# A visibly fake caller, so no assertion depends on the developer's directory.
FAKE_CALLER = "example-project"

# Substitutions a notification text may take. A label, an entry name or a display
# prompt is user data that is meant to be shown; a secret value, a code or a
# passphrase is not, and a new substitution outside this set fails the text test.
ALLOWED_SUBSTITUTIONS = {"a.label", "a.name", "prompt", "label"}


@dataclass(frozen=True)
class Source:
    """A source line that supplies a piece of a notification.

    `fragment` is the exact text expected on that line: a quoted literal, an
    f-string expression, or a TypeScript backtick template. The inventory test
    checks the fragment is still there, so a moved or reworded literal is caught.
    """

    file: str
    line: int
    fragment: str


@dataclass(frozen=True)
class Row:
    """One rendered text and where it comes from.

    `text` is the message with `samples` substituted; for a CLI notification it
    excludes the ``"**<caller>**: "`` prefix. `message` is the line that supplies
    the text and `label_from` the line that supplies the action label (None when
    the notification raises no action). `caller` names the line that passes the
    text into a helper; it is None for a direct call.
    """

    text: str
    label: str
    type: str
    auto_close: bool | int
    action: bool
    entry_name: bool
    verb: str
    obj: str
    origin: str
    message: Source
    label_from: Source | None
    samples: tuple[tuple[str, str], ...] = ()
    caller: Source | None = None


@dataclass(frozen=True)
class Site:
    """One notification call site.

    `helper` is empty for a direct call. Otherwise it names the helper function
    whose parameter carries the message: the rows then come from that helper's
    callers, not from a literal inside the helper itself.
    """

    key: str
    kind: str  # "cli" or "page"
    helper: str
    rows: tuple[Row, ...]


def _cli_row(
    text: str,
    label: str,
    *,
    message: Source,
    label_from: Source,
    origin: str,
    verb: str,
    obj: str,
    entry_name: bool = False,
    samples: tuple[tuple[str, str], ...] = (),
    caller: Source | None = None,
) -> Row:
    """A CLI notification text. `_trigger` always posts type info, autoClose False
    and one action, so those values are set once here rather than repeated."""
    return Row(
        text=text,
        label=label,
        type="info",
        auto_close=False,
        action=True,
        entry_name=entry_name,
        verb=verb,
        obj=obj,
        origin=origin,
        message=message,
        label_from=label_from,
        samples=samples,
        caller=caller,
    )


def _read_secret_row(prompt: str, text: str, obj: str, caller_line: int) -> Row:
    """One text of the in-browser secret dialog. The helper's f-string lowercases
    the caller's prompt; the caller fragment carries both the call and the prompt
    literal, so a reworded prompt fails instead of silently keeping the sample."""
    return _cli_row(
        text,
        "Enter secret",
        message=Source(VCLI, 66, 'f"Enter {prompt[0].lower()}{prompt[1:]}"'),
        label_from=Source(VCLI, 65, '"Enter secret"'),
        caller=Source(VCLI, caller_line, f'_read_secret(a, "{prompt}"'),
        origin=(f"helper f-string at line 66; prompt supplied at line {caller_line}; "
                f"sample {prompt}"),
        verb="Enter",
        obj=obj,
        samples=(("prompt", prompt),),
    )


SITES: tuple[Site, ...] = (
    # _run holds the one _trigger that cmd_create and cmd_get call directly and
    # that browser_step calls for every vault notification. Its texts are the
    # messages its callers pass; a new caller must add its message here.
    Site(
        key=f"{CLI}:488",
        kind="cli",
        helper="_run",
        rows=(
            _cli_row(
                "Register a passkey", "Register passkey",
                message=Source(CLI, 533, '"Register a passkey"'),
                label_from=Source(CLI, 533, '"Register passkey"'),
                caller=Source(CLI, 531, "_run("),
                origin="literal in cmd_create, passed to _run",
                verb="Register", obj="passkey",
            ),
            _cli_row(
                "Approve the passkey request", "Approve passkey",
                message=Source(CLI, 555, '"Approve the passkey request"'),
                label_from=Source(CLI, 555, '"Approve passkey"'),
                caller=Source(CLI, 555, "_run("),
                origin="literal in cmd_get, passed to _run",
                verb="Approve", obj="passkey",
            ),
            _cli_row(
                "Add a passkey to the vault", "Add passkey",
                message=Source(VCLI, 447, '"Add a passkey to the vault"'),
                label_from=Source(VCLI, 446, '"Add passkey"'),
                caller=Source(VCLI, 446, "browser_step("),
                origin="literal in _add_passkey, passed through browser_step to _run",
                verb="Add", obj="passkey",
            ),
            _cli_row(
                "Unlock the vault with your passkey", "Unlock vault",
                message=Source(VCLIENT, 274, '"Unlock the vault with your passkey"'),
                label_from=Source(VCLIENT, 277, '"Unlock vault"'),
                caller=Source(VCLIENT, 277, "self._one_notification("),
                origin="literal in the passkey branch of Vault.unlock",
                verb="Unlock", obj="vault",
            ),
            _cli_row(
                "Choose how to unlock the vault", "Unlock vault",
                message=Source(VCLIENT, 276, '"Choose how to unlock the vault"'),
                label_from=Source(VCLIENT, 277, '"Unlock vault"'),
                caller=Source(VCLIENT, 277, "self._one_notification("),
                origin="literal in the no-passkey branch of Vault.unlock",
                verb="Choose", obj="vault",
            ),
            _cli_row(
                "Create the vault", "Set up vault",
                message=Source(VCLIENT, 365, '"Create the vault"'),
                label_from=Source(VCLIENT, 364, '"Set up vault"'),
                caller=Source(VCLIENT, 364, "self._one_notification("),
                origin="literal in Vault._setup",
                verb="Create", obj="vault",
            ),
        ),
    ),
    Site(
        key=f"{CLI}:596",
        kind="cli",
        helper="",
        rows=(
            _cli_row(
                "Enter the secret", "Enter secret",
                message=Source(CLI, 599, '"Enter the secret"'),
                label_from=Source(CLI, 598, '"Enter secret"'),
                origin="false branch of the a.twice ternary in cmd_passphrase",
                verb="Enter", obj="secret",
            ),
            _cli_row(
                "Enter the passphrase", "Enter passphrase",
                message=Source(CLI, 599, '"Enter the passphrase"'),
                label_from=Source(CLI, 598, '"Enter passphrase"'),
                origin="true branch of the a.twice ternary in cmd_passphrase",
                verb="Enter", obj="passphrase",
            ),
        ),
    ),
    Site(
        key=f"{CLI}:741",
        kind="cli",
        helper="",
        rows=(
            _cli_row(
                "Copy **example-secret**", "Copy to clipboard",
                message=Source(CLI, 720, 'f"Copy **{a.label}**"'),
                label_from=Source(CLI, 741, '"Copy to clipboard"'),
                origin="f-string in cmd_copy; a.label is --label; sample example-secret",
                verb="Copy", obj="example-secret", entry_name=True,
                samples=(("a.label", "example-secret"),),
            ),
        ),
    ),
    Site(
        key=f"{CLI}:815",
        kind="cli",
        helper="",
        rows=(
            _cli_row(
                "Show **example-secret**", "Show the code",
                message=Source(CLI, 805, 'f"Show **{a.label}**"'),
                label_from=Source(CLI, 815, '"Show the code"'),
                origin="f-string in cmd_show; a.label is --label; sample example-secret",
                verb="Show", obj="example-secret", entry_name=True,
                samples=(("a.label", "example-secret"),),
            ),
        ),
    ),
    # _read_secret raises the in-browser dialog for every secret prompt. Its nine
    # callers supply the prompt that becomes the message.
    Site(
        key=f"{VCLI}:65",
        kind="cli",
        helper="_read_secret",
        rows=(
            _read_secret_row("Password", "Enter password", "password", 95),
            _read_secret_row("Recovery passphrase", "Enter recovery passphrase",
                             "passphrase", 142),
            _read_secret_row("Recovery passphrase", "Enter recovery passphrase",
                             "passphrase", 166),
            _read_secret_row("Unlock password", "Enter unlock password",
                             "password", 177),
            _read_secret_row("Code of the authenticator app",
                             "Enter code of the authenticator app", "code", 179),
            _read_secret_row("pass-cli master password", "Enter pass-cli master password",
                             "password", 391),
            _read_secret_row("Current recovery passphrase",
                             "Enter current recovery passphrase", "passphrase", 485),
            _read_secret_row("New recovery passphrase", "Enter new recovery passphrase",
                             "passphrase", 486),
            _read_secret_row("Recovery passphrase", "Enter recovery passphrase",
                             "passphrase", 507),
        ),
    ),
    Site(
        key=f"{VCLI}:304",
        kind="cli",
        helper="_stage_and_trigger",
        rows=(
            _cli_row(
                "Copy **example-entry**", "Copy to clipboard",
                message=Source(VCLI, 315, 'f"Copy **{a.name}**"'),
                label_from=Source(VCLI, 314, '"Copy to clipboard"'),
                caller=Source(VCLI, 314, "_stage_and_trigger("),
                origin="literal in cmd_copy, passed to _stage_and_trigger; a.name is "
                       "the entry name; sample example-entry",
                verb="Copy", obj="example-entry", entry_name=True,
                samples=(("a.name", "example-entry"),),
            ),
            _cli_row(
                "Show **example-entry**", "Show",
                message=Source(VCLI, 322, 'f"Show **{a.name}**"'),
                label_from=Source(VCLI, 321, '"Show"'),
                caller=Source(VCLI, 321, "_stage_and_trigger("),
                origin="literal in cmd_show, passed to _stage_and_trigger; a.name is "
                       "the entry name; sample example-entry",
                verb="Show", obj="example-entry", entry_name=True,
                samples=(("a.name", "example-entry"),),
            ),
        ),
    ),
    # _one_notification raises the vault unlock/set-up notification through
    # browser_step; its callers supply the message.
    Site(
        key=f"{VCLIENT}:277",
        kind="cli",
        helper="_one_notification",
        rows=(
            _cli_row(
                "Unlock the vault with your passkey", "Unlock vault",
                message=Source(VCLIENT, 274, '"Unlock the vault with your passkey"'),
                label_from=Source(VCLIENT, 277, '"Unlock vault"'),
                caller=Source(VCLIENT, 277, "self._one_notification("),
                origin="literal in the passkey branch of Vault.unlock",
                verb="Unlock", obj="vault",
            ),
            _cli_row(
                "Choose how to unlock the vault", "Unlock vault",
                message=Source(VCLIENT, 276, '"Choose how to unlock the vault"'),
                label_from=Source(VCLIENT, 277, '"Unlock vault"'),
                caller=Source(VCLIENT, 277, "self._one_notification("),
                origin="literal in the no-passkey branch of Vault.unlock",
                verb="Choose", obj="vault",
            ),
        ),
    ),
    Site(
        key=f"{VCLIENT}:364",
        kind="cli",
        helper="_one_notification",
        rows=(
            _cli_row(
                "Create the vault", "Set up vault",
                message=Source(VCLIENT, 365, '"Create the vault"'),
                label_from=Source(VCLIENT, 364, '"Set up vault"'),
                caller=Source(VCLIENT, 364, "self._one_notification("),
                origin="literal in Vault._setup",
                verb="Create", obj="vault",
            ),
        ),
    ),
    Site(
        key=f"{COPY_TS}:144",
        kind="page",
        helper="",
        rows=(
            Row(
                text="Clipboard refused - no secret name",
                label="", type="warning", auto_close=False, action=False,
                entry_name=False, verb="refused", obj="Clipboard",
                origin="literal first argument of Notification.emit",
                message=Source(COPY_TS, 144, "'Clipboard refused - no secret name'"),
                label_from=None,
            ),
        ),
    ),
    Site(
        key=f"{COPY_TS}:150",
        kind="page",
        helper="",
        rows=(
            Row(
                text="Clipboard refused - copy **example-entry** again",
                label="Copy to clipboard", type="warning", auto_close=False,
                action=True, entry_name=True, verb="copy", obj="example-entry",
                origin="template literal one line above; ${label} is the secret name; "
                       "sample example-entry",
                message=Source(COPY_TS, 149, "`Clipboard refused - copy **${label}** again`"),
                label_from=Source(COPY_TS, 154, "'Copy to clipboard'"),
                samples=(("label", "example-entry"),),
            ),
        ),
    ),
    Site(
        key=f"{SHOW_TS}:38",
        kind="page",
        helper="",
        rows=(
            Row(
                text="Code refused - no secret name",
                label="", type="warning", auto_close=False, action=False,
                entry_name=False, verb="refused", obj="Code",
                origin="literal first argument of Notification.emit",
                message=Source(SHOW_TS, 38, "'Code refused - no secret name'"),
                label_from=None,
            ),
        ),
    ),
    Site(
        key=f"{PLUGIN_TS}:128",
        kind="page",
        helper="",
        rows=(
            Row(
                text="Vault unlocked",
                label="", type="success", auto_close=3000, action=False,
                entry_name=False, verb="unlocked", obj="Vault",
                origin="translated literal passed to the notifications ingest; the "
                       "local Notification.emit is the fallback",
                message=Source(PLUGIN_TS, 207, "trans.__('Vault unlocked')"),
                label_from=None,
                caller=Source(PLUGIN_TS, 205, "raiseUnlockedToast("),
            ),
        ),
    ),
)

# One row per rendered text: a ternary branch or a helper caller adds a row.
ROWS: tuple[Row, ...] = tuple(row for site in SITES for row in site.rows)


# --------------------------------------------------------------------------- #
# source access
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=None)
def _lines(file: str) -> tuple[str, ...]:
    """The lines of a repo-relative file; rows carry 1-based line numbers."""
    return (ROOT / file).read_text(encoding="utf-8").splitlines()


@lru_cache(maxsize=None)
def _python_files() -> tuple[tuple[str, ast.Module], ...]:
    """Every product Python file with its parsed tree. Tests and caches are out:
    this collector is about call sites the product ships."""
    files = []
    for path in sorted((ROOT / "jupyterlab_passkey_extension").rglob("*.py")):
        rel = path.relative_to(ROOT)
        if "tests" in rel.parts or "__pycache__" in rel.parts:
            continue
        files.append((rel.as_posix(),
                      ast.parse(path.read_text(encoding="utf-8"), filename=str(rel))))
    return tuple(files)


@lru_cache(maxsize=None)
def _functions() -> dict[str, tuple[tuple[int, int, str], ...]]:
    """(start, end, name) for every function and method, keyed by file."""
    found: dict[str, tuple[tuple[int, int, str], ...]] = {}
    for rel, tree in _python_files():
        found[rel] = tuple(
            (node.lineno, node.end_lineno, node.name)
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
    return found


def _function_named(name: str) -> tuple[str, int, int]:
    """The file and line span of the one product function with this name."""
    matches = [
        (rel, start, end)
        for rel, spans in _functions().items()
        for start, end, found in spans
        if found == name
    ]
    assert len(matches) == 1, f"expected one function named {name!r}, found {matches}"
    return matches[0]


def _function_source(name: str) -> str:
    """The source lines of the one product function with this name."""
    file, start, end = _function_named(name)
    return "\n".join(_lines(file)[start - 1:end])


def _enclosing_function(file: str, line: int) -> tuple[int, int, str] | None:
    """The innermost function containing a line, or None at module level."""
    spans = [s for s in _functions().get(file, ()) if s[0] <= line <= s[1]]
    return min(spans, key=lambda s: s[1] - s[0]) if spans else None


def _discovered() -> tuple[str, ...]:
    """Every notification call site in the product tree, as `file:line`.

    Python: a Call whose name is `_trigger` or `_one_notification`. The function
    definitions are FunctionDef nodes, not calls, so they are never counted.
    TypeScript: every `Notification.emit(` in `src/`, with tests and declarations
    left out. shortcut: one site per line; split if a line ever carries two.
    """
    keys: set[str] = set()
    for rel, tree in _python_files():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute)
                    else None)
            if name in {"_trigger", "_one_notification"}:
                keys.add(f"{rel}:{node.lineno}")
    for path in sorted((ROOT / "src").rglob("*.ts")):
        rel = path.relative_to(ROOT)
        if "__tests__" in rel.parts or path.name.endswith(".d.ts"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "Notification.emit(" in line:
                keys.add(f"{rel.as_posix()}:{number}")
    return tuple(sorted(keys))


def _line(file: str, number: int) -> str:
    lines = _lines(file)
    assert 1 <= number <= len(lines), f"{file}:{number} is outside the file"
    return lines[number - 1]


def _assert_source(source: Source) -> None:
    """Fail naming the file and line when the declared source fragment is gone."""
    line = _line(source.file, source.line)
    assert source.fragment in line, (
        f"{source.file}:{source.line} no longer contains {source.fragment!r}; "
        f"the line now reads {line.strip()!r}"
    )


def _row_key(site: Site, row: Row) -> tuple[object, ...]:
    """A row is one text: the same site, source and caller cannot appear twice."""
    caller = (row.caller.file, row.caller.line) if row.caller else None
    return (site.key, row.message.file, row.message.line, row.message.fragment,
            caller, row.text)


# --------------------------------------------------------------------------- #
# reading the text out of the source
# --------------------------------------------------------------------------- #


def _render_python_fstring(node: ast.JoinedStr, samples: dict[str, str]) -> str:
    """Render an f-string read from the product source, using the row's samples.

    A whole expression in `samples` (such as `a.label`) is substituted directly;
    otherwise the expression is evaluated against the samples, which covers the
    helper's `prompt[0].lower()` and `prompt[1:]`. The expressions come from this
    repository's own source, never from external input.
    """
    parts = []
    for value in node.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value))
            continue
        assert isinstance(value, ast.FormattedValue), f"unsupported part {value!r}"
        expression = ast.unparse(value.value)
        if expression in samples:
            parts.append(samples[expression])
            continue
        try:
            parts.append(str(eval(expression, {"__builtins__": {}}, dict(samples))))
        except Exception as error:
            raise AssertionError(
                f"cannot render {expression!r} with samples {samples!r}: {error}"
            ) from error
    return "".join(parts)


def _rendered_text(row: Row) -> str:
    """The text the declared source actually renders, with the row's samples."""
    fragment = row.message.fragment
    if row.message.file.endswith(".py"):
        expression = ast.parse(fragment, mode="eval").body
        if isinstance(expression, ast.Constant):
            assert isinstance(expression.value, str)
            return expression.value
        assert isinstance(expression, ast.JoinedStr), f"not a string: {fragment}"
        return _render_python_fstring(expression, dict(row.samples))
    if fragment.startswith("`"):
        text = fragment[1:-1]
        for name, value in row.samples:
            text = text.replace("${" + name + "}", value)
        assert "${" not in text, f"unsubstituted placeholder in {fragment}"
        return text
    match = re.search(r"'([^']*)'", fragment)
    assert match, f"no string literal in {fragment}"
    return match.group(1)


def _literal_value(fragment: str) -> str:
    """The string a literal source fragment holds, Python or TypeScript."""
    if fragment.startswith(("'", '"')):
        try:
            value = ast.literal_eval(fragment)
        except (ValueError, SyntaxError):
            value = None
        if isinstance(value, str):
            return value
    match = re.search(r"'([^']*)'", fragment)
    assert match, f"no string literal in {fragment}"
    return match.group(1)


def _trigger_payload() -> dict[str, ast.expr]:
    """The payload dict of `_trigger`, keyed by its string keys."""
    for rel, tree in _python_files():
        if rel != CLI:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != "_trigger":
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Dict):
                    continue
                pairs = {}
                for key, value in zip(child.keys, child.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        pairs[key.value] = value
                if "message" in pairs:
                    return pairs
    raise AssertionError(f"{CLI}: no payload dict in _trigger")


def _emit_block(site: Site) -> str:
    """The full `Notification.emit(...)` call, from the site line to its `)`."""
    path, number = site.key.rsplit(":", 1)
    text = "\n".join(_lines(path)[int(number) - 1:])
    start = text.index("Notification.emit(")
    depth = 0
    for offset, char in enumerate(text[start:], start):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:offset + 1]
    raise AssertionError(f"{site.key}: unbalanced Notification.emit call")


# --------------------------------------------------------------------------- #
# 1. inventory
# --------------------------------------------------------------------------- #


def test_the_notification_call_site_count_is_exact():
    discovered = _discovered()
    assert len(discovered) == EXPECTED_CALL_SITES, (
        f"discovered {len(discovered)} notification call sites, expected "
        f"{EXPECTED_CALL_SITES}: {list(discovered)}. A new notification must add "
        "its site and row(s) to SITES and raise EXPECTED_CALL_SITES."
    )


def test_inventory_matches_the_declared_call_sites():
    discovered = set(_discovered())
    declared = {site.key for site in SITES}
    missing = sorted(discovered - declared)
    gone = sorted(declared - discovered)
    assert not missing, "notification call sites with no table row:\n" + "\n".join(missing)
    assert not gone, "table rows whose call site disappeared:\n" + "\n".join(gone)


def test_every_site_has_rows_and_no_row_is_duplicated():
    site_keys = [site.key for site in SITES]
    assert len(site_keys) == len(set(site_keys)), f"duplicate site: {site_keys}"
    assert len(site_keys) == EXPECTED_CALL_SITES, (
        f"SITES has {len(site_keys)} entries, EXPECTED_CALL_SITES is "
        f"{EXPECTED_CALL_SITES}")
    assert len(ROWS) == EXPECTED_ROWS, (
        f"the table has {len(ROWS)} rendered texts, EXPECTED_ROWS is {EXPECTED_ROWS}")
    empty = [site.key for site in SITES if not site.rows]
    assert not empty, f"site(s) with no rendered text: {empty}"
    row_keys = [_row_key(site, row) for site in SITES for row in site.rows]
    duplicates = sorted({key for key in row_keys if row_keys.count(key) > 1})
    assert not duplicates, f"row(s) declared twice: {duplicates}"


def test_helper_sites_take_their_texts_from_callers():
    for site in SITES:
        if not site.helper:
            continue
        assert site.rows, f"{site.key}: helper {site.helper} declares no rendered text"
        file, start, end = _function_named(site.helper)
        for row in site.rows:
            assert row.caller is not None, (
                f"{site.key}: helper row has no caller line")
            entry_points = _HELPER_ENTRY_POINTS[site.helper]
            assert any(name in row.caller.fragment for name in entry_points), (
                f"{site.key}: caller {row.caller.file}:{row.caller.line} does not "
                f"reach {site.helper}; expected one of {entry_points}")
            assert not (row.caller.file == file and start <= row.caller.line <= end), (
                f"{site.key}: caller {row.caller.file}:{row.caller.line} is inside "
                f"{site.helper}; a helper row must name a caller's text")


# --------------------------------------------------------------------------- #
# 2. rows: the declared text is the text the source renders
# --------------------------------------------------------------------------- #


def test_every_row_points_at_the_text_it_describes():
    for site in SITES:
        site_line = int(site.key.rsplit(":", 1)[1])
        for row in site.rows:
            _assert_source(row.message)
            if row.label_from is not None:
                _assert_source(row.label_from)
            if row.caller is not None:
                _assert_source(row.caller)

            actual = _rendered_text(row)
            assert actual == row.text, (
                f"{site.key}: {row.message.file}:{row.message.line} renders "
                f"{actual!r}, the row says {row.text!r}")

            if row.label_from is not None:
                label = _literal_value(row.label_from.fragment)
                assert label == row.label, (
                    f"{site.key}: {row.label_from.file}:{row.label_from.line} "
                    f"renders label {label!r}, the row says {row.label!r}")

            if row.caller is None and site.kind == "cli":
                span = _enclosing_function(row.message.file, row.message.line)
                assert span is not None, (
                    f"{site.key}: message source is not inside a function")
                assert span[0] <= site_line <= span[1], (
                    f"{site.key}: message at {row.message.file}:{row.message.line} "
                    f"is outside {span[2]}, the function that calls the notification")
            if row.caller is None and site.kind == "page":
                assert row.message.line in (site_line, site_line - 1), (
                    f"{site.key}: page text must be on the call line or the line above")


# --------------------------------------------------------------------------- #
# 3. text rules
# --------------------------------------------------------------------------- #

_BANNED = ("click", "open the notification", "press", "please", "successfully",
           "asked by")
_URL = re.compile(
    r"(?:https?://|wss?://|www\.|\blocalhost\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|"
    r"\b[\w.-]+\.(?:com|org|net|io)\b)",
    re.I,
)
_COMMAND_ID = re.compile(r"(?:jupyterlab-passkey|passkey:[\w-]+)", re.I)
_IMPERATIVE = {"register", "approve", "enter", "copy", "show", "unlock", "set", "add"}

# The call on the caller's line that carries the text toward the helper. `_run` is
# reached directly by cmd_create/cmd_get and through browser_step (itself called by
# _one_notification) for every vault notification; the other helpers are direct.
_HELPER_ENTRY_POINTS = {
    "_run": ("_run", "browser_step", "_one_notification"),
    "_read_secret": ("_read_secret",),
    "_stage_and_trigger": ("_stage_and_trigger",),
    "_one_notification": ("_one_notification",),
}


def _cli_rows() -> list[Row]:
    return [row for site in SITES if site.kind == "cli" for row in site.rows]


def test_cli_texts_carry_the_bold_caller_prefix():
    payload = _trigger_payload()
    assert ast.unparse(payload["message"]) == "f'**{_caller()}**: {message}'", (
        "the CLI prefix must render '**<caller>**: ' before the message")
    assert ast.literal_eval(payload["type"]) == "info"
    assert ast.literal_eval(payload["autoClose"]) is False
    # A transient row leaves the centre when the centre opens, and the row must
    # keep its button for the press that answers it: no transient key.
    assert "transient" not in payload
    actions = payload["actions"]
    assert isinstance(actions, ast.List) and len(actions.elts) == 1
    action = actions.elts[0]
    assert isinstance(action, ast.Dict)
    action_pairs = {
        key.value: value for key, value in zip(action.keys, action.values)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    assert ast.unparse(action_pairs["label"]) == "label"
    for name in ("_trigger", "_caller"):
        assert "Asked by" not in _function_source(name), (
            f"{name} still renders the old 'Asked by' prefix")

    for row in _cli_rows():
        full = f"**{FAKE_CALLER}**: " + row.text
        assert full.startswith("**") and "**: " in full
        assert "\n" not in full and "\r" not in full
        lowered = full.lower()
        assert "asked by" not in lowered


def test_messages_fit_sixty_characters_and_avoid_instructions():
    # The 60-character bound is checked with the row's fake sample. A caller can
    # pass a longer --label or a vault entry name (the vault allows 200), and the
    # code does not cut it, so this test cannot bound an arbitrary user name.
    for site in SITES:
        for row in site.rows:
            assert len(row.text) <= 60, (
                f"{site.key}: {len(row.text)} characters after the prefix: "
                f"{row.text!r}")
            assert "\n" not in row.text and "\r" not in row.text
            lowered = row.text.lower()
            for word in _BANNED:
                assert word not in lowered, (
                    f"{site.key}: {word!r} in {row.text!r}")
            assert not _URL.search(row.text), (
                f"{site.key}: URL in {row.text!r}")
            assert not _COMMAND_ID.search(row.text), (
                f"{site.key}: command id in {row.text!r}")
            # The verb and object are chosen by a human; the machine check is that
            # both are present, so a reword that drops one fails.
            assert row.verb.lower() in lowered, (
                f"{site.key}: action {row.verb!r} missing from {row.text!r}")
            assert row.obj.lower() in lowered, (
                f"{site.key}: object {row.obj!r} missing from {row.text!r}")
            for name, _ in row.samples:
                assert name in ALLOWED_SUBSTITUTIONS, (
                    f"{site.key}: substitution {name!r} may carry a secret; only "
                    "a label, entry name or prompt may reach the text")


def test_labels_are_short_imperatives_that_do_not_repeat_the_message():
    for site in SITES:
        for row in site.rows:
            assert row.action == bool(row.label), (
                f"{site.key}: action={row.action} with label={row.label!r}")
            if not row.label:
                continue
            words = row.label.split()
            # Whether the wording is the best one is a human judgement; one to four
            # words starting with a known imperative is the checkable part.
            assert 1 <= len(words) <= 4, (
                f"{site.key}: label {row.label!r} is not a short phrase")
            assert words[0].strip(":").lower() in _IMPERATIVE, (
                f"{site.key}: label {row.label!r} does not start with an imperative")
            label = row.label.lower().strip("* ")
            text = row.text.lower().strip("* ")
            assert label != text, (
                f"{site.key}: label repeats the message {row.text!r}")
            for word in _BANNED:
                assert word not in row.label.lower(), (
                    f"{site.key}: {word!r} in label {row.label!r}")


def test_a_vault_entry_name_is_bold_where_the_message_names_one():
    for site in SITES:
        for row in site.rows:
            if not row.entry_name:
                continue
            assert row.samples, f"{site.key}: an entry text must name the entry"
            for _, value in row.samples:
                assert f"**{value}**" in row.text, (
                    f"{site.key}: {value!r} is not markdown bold in {row.text!r}")
            # Whether the bold name sits at the object position is a human reading;
            # the checkable part is that the name is bold inside the same line.
            assert row.text.count("**") == 2, (
                f"{site.key}: exactly one bold name expected in {row.text!r}")


def test_page_notifications_match_their_type_auto_close_and_action():
    for site in SITES:
        if site.kind != "page":
            continue
        path, number = site.key.rsplit(":", 1)
        line = _line(path, int(number))
        block = _emit_block(site)
        for row in site.rows:
            assert f"'{row.type}'" in line, (
                f"{site.key}: type {row.type!r} is not on the emit line")
            if row.auto_close is False:
                assert re.search(r"autoClose:\s*false", block), (
                    f"{site.key}: autoClose false is not in the options")
            else:
                assert re.search(rf"autoClose:\s*{row.auto_close}", block), (
                    f"{site.key}: autoClose {row.auto_close} is not in the options")
            assert ("actions:" in block) == row.action, (
                f"{site.key}: actions presence does not match action={row.action}")
            if row.action:
                assert row.label and row.label in block, (
                    f"{site.key}: action label {row.label!r} is not in the options")
            else:
                assert "label:" not in block, (
                    f"{site.key}: a notification with no action carries a label")


def test_the_success_toast_carries_no_label_and_closes_in_three_seconds():
    site = next(site for site in SITES if site.key == f"{PLUGIN_TS}:128")
    row = site.rows[0]
    assert (row.type, row.auto_close, row.label, row.action) == (
        "success", 3000, "", False)
    block = _emit_block(site)
    assert "actions:" not in block and "label:" not in block
