import os
import re
import sqlite3
import zlib

try:
    import zstandard
except ImportError:
    zstandard = None

DEFAULT_DB = os.environ.get("IDA_MCP_PSEUDO_DB", "")

_DICTS = {}


def _load_dict(con, path):
    key = (path, os.path.getmtime(path))
    if key not in _DICTS:
        _DICTS.clear()
        raw = con.execute("SELECT v FROM meta WHERE k='dict'").fetchone()
        _DICTS[key] = zstandard.ZstdCompressionDict(raw[0]) if raw else None
    return _DICTS[key]


def _decoder(con, path):
    try:
        row = con.execute("SELECT v FROM meta WHERE k='codec'").fetchone()
    except sqlite3.OperationalError:
        row = None
    codec = bytes(row[0]).decode() if row else "zlib"
    if codec == "zlib":
        return zlib.decompress
    if codec != "zstd":
        raise ValueError(f"unknown pseudo db codec: {codec!r}")
    if zstandard is None:
        raise RuntimeError("pseudo db uses zstd but the zstandard package is not installed")
    dctx = zstandard.ZstdDecompressor(dict_data=_load_dict(con, path))
    return dctx.decompress


class _Con(sqlite3.Connection):
    decode = None


def _open(path):
    path = path or DEFAULT_DB
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"pseudo db not found: {path!r} (set IDA_MCP_PSEUDO_DB or pass db=)")
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, factory=_Con)
    con.execute("PRAGMA mmap_size=4294967296")
    con.decode = _decoder(con, path)
    return con


_COLS = "f.module, m.name, f.ea, f.name, f.size, f.callees, f.callers, f.code"
_FROM = "FROM funcs f JOIN modules m ON m.id = f.module"
_SEL = f"SELECT {_COLS} {_FROM}"


def _check_schema(con):
    cols = [r[1] for r in con.execute("PRAGMA table_info(funcs)")]
    if "module" not in cols:
        raise RuntimeError("pseudo db uses the old single-module schema; rebuild it with scripts/pseudo_db.py")


def _modules(con):
    return [r[0] for r in con.execute("SELECT name FROM modules ORDER BY name")]


def _module_ids(con, name):
    """Module ids matching 'server.dll' or just 'server'. None name = every module."""
    if not name:
        return None
    n = name.strip().lower()
    rows = con.execute(
        "SELECT id FROM modules WHERE name=? OR substr(name, 1, length(?) + 1) = ? || '.'", (n, n, n)
    ).fetchall()
    return [r[0] for r in rows]


def _in(ids):
    return "(" + ",".join(str(int(i)) for i in ids) + ")"


def _split_target(target):
    t = str(target).strip()
    if "!" in t:
        mod, rest = t.split("!", 1)
        return mod.strip(), rest.strip()
    return None, t


def _resolve(con, target, module=None):
    """Return (rows, error). Several rows means the target is ambiguous."""
    mod, t = _split_target(target)
    mod = mod or module
    ids = _module_ids(con, mod)
    if ids is not None and not ids:
        return [], f"module not found: {mod} (available: {', '.join(_modules(con)) or 'none'})"
    scope = f" AND f.module IN {_in(ids)}" if ids else ""

    rows = []
    try:
        ea = int(t, 16) if t.lower().startswith("0x") else int(t)
    except ValueError:
        ea = None
    if ea is not None:
        for (mid,) in con.execute(f"SELECT id FROM modules" + (f" WHERE id IN {_in(ids)}" if ids else "")).fetchall():
            row = con.execute(f"{_SEL} WHERE f.module=? AND f.ea<=? ORDER BY f.ea DESC LIMIT 1", (mid, ea)).fetchone()
            if row and ea < row[2] + max(row[4], 1):
                rows.append(row)
    if not rows:
        rows = con.execute(f"{_SEL} WHERE f.name=?{scope} ORDER BY m.name, f.ea", (t,)).fetchall()
    return rows, None


def _fmt(row, decode):
    _mid, mod, ea, name, size, callees, callers, code = row
    body = decode(code).decode("utf-8", "replace")
    return f"//==== {mod}!{name} @ {ea:#x} size={size} ====\n// callers: {callers or '-'}\n// callees: {callees or '-'}\n{body}"


def get_pseudo(target, depth=0, max_chars=1_073_741_824, db=None):
    """target: one function name/address, or a list of them. Prefix with 'module!' (e.g.
    'server.dll!0x1000' or 'server!Foo') to pick a module when the DB holds several.
    All targets share one max_chars budget and one de-duplication set; each target's
    callees (up to depth) follow that target's own block."""
    if isinstance(target, (list, tuple)):
        targets = [str(t) for t in target]
    else:
        targets = [str(target)]
    if not targets:
        return "no targets given"
    con = _open(db)
    try:
        _check_schema(con)
        seen, out, total = set(), [], 0
        for i, t in enumerate(targets):
            rows, err = _resolve(con, t)
            if err:
                out.append(err)
                continue
            if not rows:
                out.append(f"not found: {t}")
                continue
            if len(rows) > 1:
                opts = ", ".join(f"{r[1]}!{r[2]:#x}" for r in rows[:20])
                out.append(f"ambiguous: {t} matches {len(rows)} functions; qualify it as module!name or module!address: {opts}")
                continue
            todo = [(rows[0], 0)]
            while todo:
                row, d = todo.pop(0)
                key = (row[0], row[2])
                if key in seen:
                    continue
                seen.add(key)
                text = _fmt(row, con.decode)
                if total + len(text) > max_chars:
                    out.append(f"// TRUNCATED at {max_chars} chars; call again for: {row[1]}!{row[3]}")
                    rest = targets[i + 1 :]
                    if rest:
                        out.append("// targets not returned (call again): " + ", ".join(rest))
                    return "\n".join(out)
                out.append(text)
                total += len(text)
                if d < depth and row[5]:
                    for name in row[5].split(","):
                        name = name.strip()
                        # prefer the caller's own module, fall back to any other
                        child = con.execute(f"{_SEL} WHERE f.module=? AND f.name=?", (row[0], name)).fetchone() or con.execute(
                            f"{_SEL} WHERE f.name=? ORDER BY m.name LIMIT 1", (name,)
                        ).fetchone()
                        if child:
                            todo.append((child, d + 1))
        return "\n".join(out)
    finally:
        con.close()


def search_pseudo(pattern, limit=20, db=None, module=None):
    con = _open(db)
    try:
        _check_schema(con)
        ids = _module_ids(con, module)
        if ids is not None and not ids:
            return f"module not found: {module} (available: {', '.join(_modules(con)) or 'none'})"
        scope = f" WHERE f.module IN {_in(ids)}" if ids else ""
        rx = re.compile(pattern, re.I)
        hits = []
        for mod, ea, name, code in con.execute(f"SELECT m.name, f.ea, f.name, f.code {_FROM}{scope} ORDER BY m.name, f.ea"):
            if rx.search(name):
                hits.append(f"{mod}!{ea:#x} {name} (name)")
            else:
                for line in con.decode(code).decode("utf-8", "replace").splitlines():
                    if rx.search(line):
                        hits.append(f"{mod}!{ea:#x} {name}: {line.strip()[:160]}")
                        break
            if len(hits) >= limit:
                break
        return "\n".join(hits) or "no matches"
    finally:
        con.close()
