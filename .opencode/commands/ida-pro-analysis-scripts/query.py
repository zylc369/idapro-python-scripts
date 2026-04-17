# -*- coding: utf-8 -*-
"""summary: IDA Pro AI 智能分析命令 — 查询操作脚本

description:
  查询 IDA 数据库信息，输出结构化 JSON 供 AI 解析。
  通过环境变量 IDA_QUERY 指定查询类型，IDA_OUTPUT 指定输出文件路径。

  支持的查询类型（IDA_QUERY）:
    entry_points — 枚举所有入口点（根据文件类型智能识别）
    functions    — 按模式匹配函数列表
    decompile    — 反编译指定函数（返回 C 伪代码）
    disassemble  — 反汇编指定函数
    func_info    — 查询单个函数的详细信息
    xrefs_to     — 查询指定地址/函数的交叉引用（谁引用了它）
    xrefs_from   — 查询指定函数调用了哪些函数
    strings      — 搜索字符串及其引用位置
    imports      — 列出所有导入函数
    exports      — 列出所有导出函数
    segments     — 列出所有段信息

  地址参数格式:
    IDA_FUNC_ADDR / IDA_ADDR 同时接受函数名（如 main、sub_401000）
    和十六进制地址（如 0x401000）。

  调用方式:
    IDA_QUERY=entry_points IDA_OUTPUT=/tmp/result.json \\
      idat -A -S"/path/to/query.py" -L/tmp/idat.log target.i64

level: intermediate
"""

import fnmatch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _base import env_str, env_int, log, run_headless

import ida_bytes
import ida_entry
import ida_funcs
import ida_idaapi
import ida_lines
import ida_loader
import ida_nalt
import ida_name
import ida_segment
import ida_xref
import idautils

try:
    import ida_hexrays
    _HAS_DECOMPILER = True
except ImportError:
    _HAS_DECOMPILER = False

MAX_MATCHES = 200
MAX_REFS_DISPLAY = 50
MAX_STRINGS_DISPLAY = 100


def _resolve_func(addr_str):
    """将函数名或十六进制地址解析为 func_t 对象。"""
    if not addr_str:
        return None
    try:
        ea = int(addr_str, 16)
        if ea < 0 or ea == ida_idaapi.BADADDR:
            ea = ida_idaapi.BADADDR
    except ValueError:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, addr_str)
    if ea == ida_idaapi.BADADDR:
        log(f"[!] 无法解析地址: {addr_str}\n")
        return None
    func = ida_funcs.get_func(ea)
    if func is None:
        log(f"[!] 地址 0x{ea:X} 不属于任何函数\n")
    return func


def _resolve_addr(addr_str):
    """将函数名或十六进制地址解析为具体地址（不要求在函数内）。"""
    if not addr_str:
        return ida_idaapi.BADADDR
    try:
        ea = int(addr_str, 16)
        if 0 <= ea < ida_idaapi.BADADDR:
            return ea
    except ValueError:
        pass
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, addr_str)
    if ea == ida_idaapi.BADADDR:
        log(f"[!] 无法解析地址: {addr_str}\n")
    return ea


def _hex(ea):
    """将地址格式化为 0x 前缀十六进制字符串。"""
    return f"0x{ea:X}"


def _get_func_name_safe(ea):
    """安全获取函数名，失败返回空字符串。"""
    name = ida_funcs.get_func_name(ea)
    return name if name else ""


def _get_file_type():
    """获取文件类型描述，用于入口点智能识别。"""
    try:
        ft = ida_loader.get_file_type_name()
        if not ft:
            return "unknown"
        ft_lower = ft.lower()
        if "dll" in ft_lower or "dynamic link library" in ft_lower:
            return "dll"
        if "shared object" in ft_lower or "elf" in ft_lower:
            return "so"
        if "pe" in ft_lower or "executable" in ft_lower or "coff" in ft_lower:
            return "exe"
        if "mach-o" in ft_lower:
            return "macho"
        return ft_lower
    except Exception:
        return "unknown"


def _query_entry_points():
    """枚举所有入口点，根据文件类型智能识别入口。"""
    log("[*] 正在查询入口点...\n")
    file_type = _get_file_type()
    log(f"[*] 文件类型: {file_type}\n")

    entries = []
    seen = set()
    eqty = ida_entry.get_entry_qty()
    for i in range(eqty):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea == ida_idaapi.BADADDR or ea in seen:
            continue
        seen.add(ea)
        name = ida_entry.get_entry_name(ordinal)
        if not name:
            name = _get_func_name_safe(ea)
        entry_type = "entry"
        if name and name.startswith("."):
            entry_type = "init_array"
        elif name in ("main", "_main", "wmain", "WinMain", "wWinMain",
                       "DllMain", "DriverEntry"):
            entry_type = "main"
        elif name in ("JNI_OnLoad", "JNI_OnUnload"):
            entry_type = "jni"
        elif name in ("_init", "init", ".init"):
            entry_type = "init"
        elif name in ("_start", "start"):
            entry_type = "crt_entry"
        elif name in ("_fini", "fini", ".fini"):
            entry_type = "fini"
        func = ida_funcs.get_func(ea)
        entries.append({
            "name": name,
            "addr": _hex(ea),
            "type": entry_type,
            "ordinal": ordinal,
            "size": func.size() if func else 0,
        })

    if file_type in ("dll", "so"):
        log(f"[*] {file_type} 类型文件，补充导出函数到入口列表\n")
        export_count = 0
        for ea in idautils.Functions():
            if ea in seen:
                continue
            name = _get_func_name_safe(ea)
            is_export = ida_bytes.is_mapped(ea) and name and not name.startswith("sub_")
            if not is_export:
                continue
            seen.add(ea)
            func = ida_funcs.get_func(ea)
            entries.append({
                "name": name,
                "addr": _hex(ea),
                "type": "export",
                "ordinal": -1,
                "size": func.size() if func else 0,
            })
            export_count += 1
        log(f"[+] 补充 {export_count} 个导出函数，共 {len(entries)} 个入口点\n")
    else:
        log(f"[+] 找到 {len(entries)} 个入口点\n")
    return {"entries": entries, "file_type": file_type, "total": len(entries)}


def _query_functions():
    """按模式匹配函数列表。"""
    pattern = env_str("IDA_PATTERN", "")
    log(f"[*] 正在查询函数列表，模式: '{pattern or '(全部)'}'\n")

    functions = []
    count = 0
    for ea in idautils.Functions():
        name = _get_func_name_safe(ea)
        if pattern and not fnmatch.fnmatch(name, pattern):
            continue
        func = ida_funcs.get_func(ea)
        functions.append({
            "name": name,
            "addr": _hex(ea),
            "size": func.size() if func else 0,
        })
        count += 1
        if count >= MAX_MATCHES:
            log(f"[!] 匹配结果超过 {MAX_MATCHES}，已截断\n")
            break

    log(f"[+] 找到 {len(functions)} 个函数\n")
    return {"functions": functions, "total": len(functions), "truncated": count >= MAX_MATCHES}


def _query_decompile():
    """反编译指定函数，返回 C 伪代码。"""
    addr_str = env_str("IDA_FUNC_ADDR", "")
    log(f"[*] 正在反编译函数: {addr_str}\n")

    func = _resolve_func(addr_str)
    if func is None:
        return {"error": f"无法解析函数: {addr_str}"}

    func_name = _get_func_name_safe(func.start_ea)
    source_type = "disassembly"
    source = ""

    if _HAS_DECOMPILER:
        try:
            if not ida_hexrays.init_hexrays_plugin():
                log("[!] 反编译器初始化失败\n")
            else:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc:
                    source = str(cfunc)
                    source_type = "decompiled"
                    log(f"[+] 反编译成功: {func_name} ({len(source.splitlines())} 行)\n")
                else:
                    log("[!] 反编译返回 None，回退到反汇编\n")
        except Exception as e:
            log(f"[!] 反编译失败: {e}，回退到反汇编\n")

    if not source:
        source = _generate_disassembly(func)
        log(f"[+] 反汇编成功: {func_name} ({len(source.splitlines())} 行)\n")

    return {
        "func_name": func_name,
        "addr": _hex(func.start_ea),
        "source": source,
        "source_type": source_type,
        "size": func.size(),
    }


def _generate_disassembly(func):
    """生成函数的完整反汇编文本。"""
    lines = []
    for chunk in ida_funcs.func_tail_iterator_t(func):
        is_main = chunk.start_ea == func.start_ea
        if not is_main:
            lines.append(f"; --- 尾块: {_hex(chunk.start_ea)} - {_hex(chunk.end_ea)} ---")
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            disasm = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS)
            lines.append(f"{_hex(ea)}    {disasm}")
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return "\n".join(lines)


def _query_disassemble():
    """反汇编指定函数。"""
    addr_str = env_str("IDA_FUNC_ADDR", "")
    log(f"[*] 正在反汇编函数: {addr_str}\n")

    func = _resolve_func(addr_str)
    if func is None:
        return {"error": f"无法解析函数: {addr_str}"}

    func_name = _get_func_name_safe(func.start_ea)
    disasm = _generate_disassembly(func)
    log(f"[+] 反汇编成功: {func_name} ({len(disasm.splitlines())} 行)\n")

    return {
        "func_name": func_name,
        "addr": _hex(func.start_ea),
        "disassembly": disasm,
        "size": func.size(),
    }


def _query_func_info():
    """查询单个函数的详细信息。"""
    addr_str = env_str("IDA_FUNC_ADDR", "")
    log(f"[*] 正在查询函数信息: {addr_str}\n")

    func = _resolve_func(addr_str)
    if func is None:
        return {"error": f"无法解析函数: {addr_str}"}

    func_name = _get_func_name_safe(func.start_ea)

    callers = []
    xb = ida_xref.xrefblk_t()
    for ref in xb.crefs_to(func.start_ea):
        caller_name = _get_func_name_safe(ref)
        callers.append({"addr": _hex(ref), "func": caller_name})
        if len(callers) >= MAX_REFS_DISPLAY:
            break

    callees = []
    seen_callees = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for ref in idautils.CodeRefsFrom(ea, 0):
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea != func.start_ea and callee.start_ea not in seen_callees:
                    seen_callees.add(callee.start_ea)
                    callee_name = _get_func_name_safe(callee.start_ea)
                    callees.append({"addr": _hex(callee.start_ea), "name": callee_name})
                    if len(callees) >= MAX_REFS_DISPLAY:
                        break
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break

    strings = []
    seen_str = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for ref in idautils.DataRefsFrom(ea):
                if ref in seen_str:
                    continue
                seen_str.add(ref)
                s = ida_bytes.get_strlit_contents(ref, -1, ida_nalt.STRTYPE_C)
                if s:
                    strings.append({"value": s.decode("utf-8", errors="replace"), "addr": _hex(ref)})
                    if len(strings) >= MAX_STRINGS_DISPLAY:
                        break
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break

    prototype = ""
    try:
        prototype = str(func.prototype) if func.prototype else ""
    except Exception:
        pass

    _FUNC_STATIC = getattr(ida_funcs, "FUNC_STATIC", None)
    flags = []
    if func.flags & ida_funcs.FUNC_LIB:
        flags.append("library")
    if _FUNC_STATIC is not None and func.flags & _FUNC_STATIC:
        flags.append("static")
    if func.flags & ida_funcs.FUNC_FRAME:
        flags.append("frame")
    if func.flags & ida_funcs.FUNC_THUNK:
        flags.append("thunk")
    if func.flags & ida_funcs.FUNC_NORET:
        flags.append("noreturn")

    log(f"[+] 函数信息: {func_name} @ {_hex(func.start_ea)}\n")
    return {
        "name": func_name,
        "addr": _hex(func.start_ea),
        "end_addr": _hex(func.end_ea),
        "size": func.size(),
        "flags": flags,
        "prototype": prototype,
        "callers": callers,
        "callees": callees,
        "strings": strings,
    }


def _query_xrefs_to():
    """查询指定地址/函数的交叉引用（谁引用了它）。"""
    addr_str = env_str("IDA_ADDR", "") or env_str("IDA_FUNC_ADDR", "")
    log(f"[*] 正在查询交叉引用（to）: {addr_str}\n")

    ea = _resolve_addr(addr_str)
    if ea == ida_idaapi.BADADDR:
        return {"error": f"无法解析地址: {addr_str}"}

    refs = []
    for xref in idautils.XrefsTo(ea, 0):
        func_name = _get_func_name_safe(xref.frm)
        xref_type = _xref_type_str(xref.type)
        refs.append({
            "from": _hex(xref.frm),
            "from_func": func_name,
            "type": xref_type,
        })
        if len(refs) >= MAX_REFS_DISPLAY:
            break

    log(f"[+] 找到 {len(refs)} 个交叉引用\n")
    return {"target": _hex(ea), "target_name": _get_func_name_safe(ea), "refs": refs, "total": len(refs)}


def _query_xrefs_from():
    """查询指定函数调用了哪些函数。"""
    addr_str = env_str("IDA_FUNC_ADDR", "")
    log(f"[*] 正在查询交叉引用（from）: {addr_str}\n")

    func = _resolve_func(addr_str)
    if func is None:
        ea = _resolve_addr(addr_str)
        if ea == ida_idaapi.BADADDR:
            return {"error": f"无法解析地址: {addr_str}"}
        refs = []
        for xref in idautils.XrefsFrom(ea, 0):
            to_func = _get_func_name_safe(xref.to)
            refs.append({"to": _hex(xref.to), "to_func": to_func, "type": _xref_type_str(xref.type)})
            if len(refs) >= MAX_REFS_DISPLAY:
                break
        return {"source": _hex(ea), "source_name": _get_func_name_safe(ea), "refs": refs, "total": len(refs)}

    refs = []
    seen = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for xref in idautils.XrefsFrom(ea, 0):
                to_func = _get_func_name_safe(xref.to)
                key = (xref.to, xref.type)
                if key not in seen:
                    seen.add(key)
                    refs.append({
                        "from": _hex(ea),
                        "to": _hex(xref.to),
                        "to_func": to_func,
                        "type": _xref_type_str(xref.type),
                    })
                    if len(refs) >= MAX_REFS_DISPLAY:
                        break
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break

    log(f"[+] 找到 {len(refs)} 个引用\n")
    return {
        "source": _hex(func.start_ea),
        "source_name": _get_func_name_safe(func.start_ea),
        "refs": refs,
        "total": len(refs),
    }


def _xref_type_str(xref_type):
    """将交叉引用类型转为可读字符串。"""
    mapping = {
        0: "unknown",
        1: "offset",
        2: "write",
        3: "read",
        4: "text",
        5: "data",
        16: "near_call",
        17: "near_jump",
        18: "far_call",
        19: "far_jump",
    }
    return mapping.get(xref_type, f"type_{xref_type}")


def _query_strings():
    """搜索字符串及其引用位置。"""
    pattern = env_str("IDA_PATTERN", "")
    log(f"[*] 正在搜索字符串，模式: '{pattern or '(全部)'}'\n")

    results = []
    strlist = idautils.Strings(False)
    for s in strlist:
        value = str(s)
        if pattern and pattern.lower() not in value.lower():
            continue
        ea = s.ea
        xrefs = []
        for xref in idautils.XrefsTo(ea, 0):
            func_name = _get_func_name_safe(xref.frm)
            xrefs.append({"from": _hex(xref.frm), "func": func_name})
            if len(xrefs) >= 10:
                break
        results.append({
            "value": value,
            "addr": _hex(ea),
            "length": s.length,
            "xrefs": xrefs,
        })
        if len(results) >= MAX_STRINGS_DISPLAY:
            log(f"[!] 字符串结果超过 {MAX_STRINGS_DISPLAY}，已截断\n")
            break

    log(f"[+] 找到 {len(results)} 个字符串\n")
    return {"strings": results, "total": len(results), "pattern": pattern}


def _query_imports():
    """列出所有导入函数。"""
    log("[*] 正在查询导入表...\n")

    modules = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = f"module_{i}"
        functions = []
        def _imp_cb(ea, name, ordinal):
            functions.append({
                "name": name if name else f"ord_{ordinal}",
                "addr": _hex(ea),
                "ordinal": ordinal,
            })
            return True
        ida_nalt.enum_import_names(i, _imp_cb)
        if functions:
            modules.append({"module": module_name, "functions": functions, "count": len(functions)})

    total = sum(len(m["functions"]) for m in modules)
    log(f"[+] 找到 {len(modules)} 个导入模块，共 {total} 个导入函数\n")
    return {"modules": modules, "total_modules": len(modules), "total_functions": total}


def _query_exports():
    """列出所有导出函数。"""
    log("[*] 正在查询导出表...\n")

    exports = []
    eqty = ida_entry.get_entry_qty()
    for i in range(eqty):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea == ida_idaapi.BADADDR:
            continue
        name = ida_entry.get_entry_name(ordinal)
        if not name:
            name = _get_func_name_safe(ea)
        exports.append({
            "name": name,
            "addr": _hex(ea),
            "ordinal": ordinal,
        })

    log(f"[+] 找到 {len(exports)} 个导出函数\n")
    return {"exports": exports, "total": len(exports)}


def _query_segments():
    """列出所有段信息。"""
    log("[*] 正在查询段信息...\n")

    segments = []
    seg_qty = ida_segment.get_qty()
    for i in range(seg_qty):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg)
        seg_type = ""
        try:
            seg_type = ida_segment.segm_class(seg)
        except Exception:
            pass
        segments.append({
            "name": name,
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": seg.size(),
            "type": seg_type,
            "perm": _seg_perm_str(seg.perm),
        })

    log(f"[+] 找到 {len(segments)} 个段\n")
    return {"segments": segments, "total": len(segments)}


def _seg_perm_str(perm):
    """将段权限位转为可读字符串。"""
    s = ""
    if perm & 1:
        s += "x"
    if perm & 2:
        s += "w"
    if perm & 4:
        s += "r"
    return s if s else "none"


_QUERY_HANDLERS = {
    "entry_points": _query_entry_points,
    "functions": _query_functions,
    "decompile": _query_decompile,
    "disassemble": _query_disassemble,
    "func_info": _query_func_info,
    "xrefs_to": _query_xrefs_to,
    "xrefs_from": _query_xrefs_from,
    "strings": _query_strings,
    "imports": _query_imports,
    "exports": _query_exports,
    "segments": _query_segments,
}


def _main():
    query_type = env_str("IDA_QUERY", "")
    if not query_type:
        log("[!] 未指定查询类型（IDA_QUERY 为空）\n")
        return {"success": False, "query": None, "data": None, "error": "IDA_QUERY 环境变量未设置"}

    handler = _QUERY_HANDLERS.get(query_type)
    if handler is None:
        available = ", ".join(sorted(_QUERY_HANDLERS.keys()))
        log(f"[!] 不支持的查询类型: {query_type}，可用类型: {available}\n")
        return {"success": False, "query": query_type, "data": None, "error": f"不支持的查询类型: {query_type}，可用: {available}"}

    log(f"[*] 查询类型: {query_type}\n")
    data = handler()

    if isinstance(data, dict) and "error" in data and "success" not in data:
        return {"success": False, "query": query_type, "data": None, "error": data["error"]}

    return {"success": True, "query": query_type, "data": data, "error": None}


run_headless(_main)
