import argparse
import os
import sqlite3
import sys
import zlib

import idapro
import idautils
import ida_auto
import ida_funcs
import ida_hexrays
import ida_name
import idaapi

try:
    import zstandard
except ImportError:
    zstandard = None

DictSamples = 500
DictSize = 112 * 1024
SampleCap = 65536
CommitEvery = 500


def BuildCallGraph():
    Funcs = {}
    Callees = {}
    Callers = {}

    for FuncEa in idautils.Functions():
        Func = ida_funcs.get_func(FuncEa)
        if Func is None:
            continue
        Funcs[Func.start_ea] = (Func.end_ea, ida_name.get_name(Func.start_ea))

    for Start in Funcs:
        Out = []
        for Head in idautils.FuncItems(Start):
            for Xref in idautils.XrefsFrom(Head, 0):
                if Xref.type not in (idaapi.fl_CN, idaapi.fl_CF):
                    continue
                TargetFunc = ida_funcs.get_func(Xref.to)
                if TargetFunc is None or TargetFunc.start_ea == Start or TargetFunc.start_ea not in Funcs:
                    continue
                if TargetFunc.start_ea not in Out:
                    Out.append(TargetFunc.start_ea)
        Callees[Start] = Out
        for Target in Out:
            Callers.setdefault(Target, set()).add(Start)

    return Funcs, Callees, Callers


def DecompileFunction(Ea):
    try:
        Result = ida_hexrays.decompile(Ea)
        if Result is None:
            return "// decompilation failed: no result"
        return str(Result)
    except ida_hexrays.DecompilationFailure as Error:
        return f"// decompilation failed: {Error}"
    except Exception as Error:
        return f"// decompilation error: {Error}"


def ParseArgs():
    Parser = argparse.ArgumentParser()
    Parser.add_argument("Idb")
    Parser.add_argument("Out")
    Parser.add_argument("--codec", dest="Codec", choices=["zlib", "zstd"], default="zstd" if zstandard else "zlib")
    Parser.add_argument("--level", dest="Level", type=int, default=9)
    return Parser.parse_args()


def Main():
    Args = ParseArgs()

    if Args.Codec == "zstd" and zstandard is None:
        print("zstandard not installed (pip install zstandard), use --codec zlib")
        return 1

    if os.path.exists(Args.Out):
        os.remove(Args.Out)

    if idapro.open_database(Args.Idb, False) != 0:
        print("Failed to open database")
        return 1

    try:
        ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available")
            return 1

        Funcs, Callees, Callers = BuildCallGraph()
        Eas = sorted(Funcs, key=lambda Ea: Funcs[Ea][0] - Ea, reverse=True)
        Total = len(Eas)
        print(f"{Total} functions")

        Con = sqlite3.connect(Args.Out)
        Con.execute("PRAGMA journal_mode=OFF")
        Con.execute("PRAGMA synchronous=OFF")
        Con.executescript("""
            CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB);
            CREATE TABLE funcs(
                ea INTEGER PRIMARY KEY,
                name TEXT,
                size INTEGER,
                callees TEXT,
                callers TEXT,
                code BLOB
            );
        """)
        Con.execute("INSERT INTO meta VALUES('codec', ?)", (Args.Codec.encode(),))

        def NameOf(Ea):
            return Funcs[Ea][1]

        def InsertRow(Ea, Text, Compress):
            End, Name = Funcs[Ea]
            Con.execute(
                "INSERT INTO funcs VALUES(?,?,?,?,?,?)",
                (
                    Ea,
                    Name,
                    End - Ea,
                    ",".join(NameOf(C) for C in Callees.get(Ea, [])),
                    ",".join(NameOf(C) for C in sorted(Callers.get(Ea, ()))),
                    Compress(Text.encode("utf-8")),
                ),
            )

        Compress = None
        if Args.Codec == "zlib":
            Compress = lambda Data: zlib.compress(Data, Args.Level)

        Pending = []

        for Index, Ea in enumerate(Eas, 1):
            End, Name = Funcs[Ea]
            print(f"{Index} / {Total}  {Name}  ({End - Ea} bytes)", flush=True)

            Text = DecompileFunction(Ea)

            if Compress is None:
                Pending.append((Ea, Text))
                if len(Pending) >= DictSamples or Index == Total:
                    Samples = [T.encode("utf-8")[:SampleCap] for _, T in Pending]
                    ZDict = None
                    try:
                        ZDict = zstandard.train_dictionary(DictSize, Samples)
                        Con.execute("INSERT INTO meta VALUES('dict', ?)", (ZDict.as_bytes(),))
                    except Exception as Error:
                        print(f"dict training failed ({Error}); using no dictionary")
                    Compressor = zstandard.ZstdCompressor(level=Args.Level, dict_data=ZDict)
                    Compress = Compressor.compress
                    for PendingEa, PendingText in Pending:
                        InsertRow(PendingEa, PendingText, Compress)
                    Pending = []
            else:
                InsertRow(Ea, Text, Compress)

            if Index % CommitEvery == 0:
                Con.commit()

        Con.execute("CREATE INDEX idx_funcs_name ON funcs(name)")
        Con.commit()
        Con.close()
        print(f"Done -> {Args.Out}")
    finally:
        idapro.close_database(False)

    return 0


if __name__ == "__main__":
    sys.exit(Main())
