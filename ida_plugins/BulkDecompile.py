import time
import zlib
import sqlite3
import idaapi
import idc
import idautils
import ida_kernwin
import ida_hexrays
import ida_funcs

MaxSize = 0x40000000
CommitEvery = 200


def GetDbPath():
    return idc.get_idb_path() + ".pseudo.db"


def GetCallees(Ea):
    Names = {}
    for Head in idautils.FuncItems(Ea):
        for To in idautils.CodeRefsFrom(Head, 0):
            Target = ida_funcs.get_func(To)
            if Target and Target.start_ea != Ea:
                Names[idc.get_func_name(Target.start_ea)] = True
    return ",".join(Names)


def GetCallers(Ea):
    Names = {}
    for From in idautils.CodeRefsTo(Ea, 0):
        Source = ida_funcs.get_func(From)
        if Source and Source.start_ea != Ea:
            Names[idc.get_func_name(Source.start_ea)] = True
    return ",".join(Names)


def OpenDb():
    Con = sqlite3.connect(GetDbPath())
    Con.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB)")
    Con.execute("INSERT OR REPLACE INTO meta VALUES('codec', ?)", (b"zlib",))
    Con.execute("CREATE TABLE IF NOT EXISTS funcs("
                "ea INTEGER PRIMARY KEY, name TEXT, size INTEGER, "
                "callees TEXT, callers TEXT, code BLOB)")
    return Con


def RunBulkDecompile():
    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.warning("Hex-Rays decompiler not available")
        return

    Con = OpenDb()
    Done = {Row[0] for Row in Con.execute("SELECT ea FROM funcs")}

    Todo = []
    for Ea in idautils.Functions():
        if Ea in Done:
            continue
        Func = ida_funcs.get_func(Ea)
        if not Func:
            continue
        Size = Func.size()
        if MaxSize and Size > MaxSize:
            continue
        Todo.append((Size, Ea))
    Todo.sort()

    Total = len(Todo)
    if not Total:
        ida_kernwin.info("Nothing to do (%d already cached)." % len(Done))
        Con.close()
        return

    StartTime = time.time()
    Count = 0
    ida_kernwin.show_wait_box("Decompiling 0/%d" % Total)
    try:
        for Size, Ea in Todo:
            if ida_kernwin.user_cancelled():
                break
            Name = idc.get_func_name(Ea)
            try:
                Code = str(ida_hexrays.decompile(Ea, None, ida_hexrays.DECOMP_NO_CACHE))
            except ida_hexrays.DecompilationFailure as E:
                Code = "// decompilation failed: " + str(E)
            except Exception as E:
                Code = "// decompilation failed: " + repr(E)
            Blob = zlib.compress(Code.encode("utf-8"), 6)
            Con.execute("INSERT OR REPLACE INTO funcs VALUES(?,?,?,?,?,?)",
                        (Ea, Name, Size, GetCallees(Ea), GetCallers(Ea), Blob))
            Count += 1
            if Count % CommitEvery == 0:
                Con.commit()
            if Count % 10 == 0:
                Elapsed = time.time() - StartTime
                Eta = Elapsed / Count * (Total - Count)
                ida_kernwin.replace_wait_box(
                    "Decompiling %d/%d (%.1f%%)\n%s  (%d B)\nETA %d min  |  Cancel to stop (progress is kept)"
                    % (Count, Total, 100.0 * Count / Total, Name, Size, Eta / 60))
    finally:
        Con.commit()
        Con.close()
        ida_kernwin.hide_wait_box()
    ida_kernwin.info("Done %d/%d functions.\nSaved to:\n%s" % (Count, Total, GetDbPath()))


class BulkDecompileModule(idaapi.plugmod_t):
    def run(self, arg):
        RunBulkDecompile()


class BulkDecompilePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    comment = ""
    help = ""
    wanted_name = "Bulk Decompile"
    wanted_hotkey = "Ctrl-Alt-D"

    def init(self):
        return BulkDecompileModule()


def PLUGIN_ENTRY():
    return BulkDecompilePlugin()
