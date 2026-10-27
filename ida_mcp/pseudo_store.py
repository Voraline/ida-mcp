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


def _resolve(con, target):
    t = str(target).strip()
    try:
        ea = int(t, 16) if t.lower().startswith("0x") else int(t)
        row = con.execute(
            "SELECT ea,name,size,callees,callers,code FROM funcs WHERE ea<=? ORDER BY ea DESC LIMIT 1", (ea,)
        ).fetchone()
        if row and ea < row[0] + max(row[2], 1):
            return row
    except ValueError:
        pass
    return con.execute("SELECT ea,name,size,callees,callers,code FROM funcs WHERE name=?", (t,)).fetchone()


def _fmt(row, decode):
    ea, name, size, callees, callers, code = row
    body = decode(code).decode("utf-8", "replace")
    return f"//==== {name} @ {ea:#x} size={size} ====\n// callers: {callers or '-'}\n// callees: {callees or '-'}\n{body}"


def get_pseudo(target, depth=0, max_chars=1_073_741_824, db=None):
    con = _open(db)
    try:
        root = _resolve(con, target)
        if not root:
            return f"not found: {target}"
        seen, out, total = set(), [], 0
        todo = [(root, 0)]
        while todo:
            row, d = todo.pop(0)
            if row[0] in seen:
                continue
            seen.add(row[0])
            text = _fmt(row, con.decode)
            if total + len(text) > max_chars:
                out.append(f"// TRUNCATED at {max_chars} chars; call again for: {row[1]}")
                break
            out.append(text)
            total += len(text)
            if d < depth and row[3]:
                for name in row[3].split(","):
                    child = con.execute(
                        "SELECT ea,name,size,callees,callers,code FROM funcs WHERE name=?", (name.strip(),)
                    ).fetchone()
                    if child:
                        todo.append((child, d + 1))
        return "\n".join(out)
    finally:
        con.close()


def search_pseudo(pattern, limit=20, db=None):
    con = _open(db)
    try:
        rx = re.compile(pattern, re.I)
        hits = []
        for ea, name, code in con.execute("SELECT ea,name,code FROM funcs"):
            if rx.search(name):
                hits.append(f"{ea:#x} {name} (name)")
            else:
                for line in con.decode(code).decode("utf-8", "replace").splitlines():
                    if rx.search(line):
                        hits.append(f"{ea:#x} {name}: {line.strip()[:160]}")
                        break
            if len(hits) >= limit:
                break
        return "\n".join(hits) or "no matches"
    finally:
        con.close()
