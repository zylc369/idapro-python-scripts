# -*- coding: utf-8 -*-
"""summary: AI 分析共享工具函数库

description:
  提供 AI 辅助分析所需的公共工具函数，包括函数匹配、符号提取、
  AI 调用、响应解析、日志输出、BFS 遍历等。供 ai_rename.py、
  ai_comment.py、ai_analyze.py 共同使用。

  本模块不包含具体的业务逻辑（重命名、注释），仅提供基础设施。
  新增分析命令时，只需在 ai_analyze.py 中注册新的子命令，
  复用本模块的工具函数即可，无需修改本模块。

level: intermediate
"""

import fnmatch
import json
import os
import re
import sys

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_typeinf
import ida_xref
import idautils

try:
    import ida_hexrays
    _HAS_DECOMPILER = True
except ImportError:
    _HAS_DECOMPILER = False


AUTO_NAME_PREFIXES = (
    "sub_",
    "dword_",
    "qword_",
    "word_",
    "byte_",
    "off_",
    "unk_",
    "asc_",
    "stru_",
    "algn_",
)
MAX_MATCHES = 100
MAX_SOURCE_LINES = 400
MAX_REFS_DISPLAY = 20
MAX_STRINGS_DISPLAY = 20
DEFAULT_MAX_DEPTH = 2

C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex",
    "_Imaginary",
})


# ─────────────────────────────────────────────────────────────
#  日志
# ─────────────────────────────────────────────────────────────

def log(msg):
    """统一日志输出：IDA 输出窗口 + headless 模式下同时输出到 stderr。

    headless 模式下 ida_kernwin.msg() 的内容会被 -L 参数捕获到日志文件，
    但不会显示在终端。通过同时写入 stderr，用户可以在 shell 中实时看到进度。
    """
    ida_kernwin.msg(msg)
    if bool(ida_kernwin.cvar.batch):
        sys.stderr.write(msg)
        sys.stderr.flush()


# ─────────────────────────────────────────────────────────────
#  通用工具
# ─────────────────────────────────────────────────────────────

def format_elapsed(seconds):
    """将秒数格式化为人类可读的时间字符串。"""
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{int(m)} 分 {s:.1f} 秒"
    if seconds < 86400:
        h, remainder = divmod(seconds, 3600)
        m, s = divmod(remainder, 60)
        return f"{int(h)} 小时 {int(m)} 分 {s:.1f} 秒"
    d, remainder = divmod(seconds, 86400)
    h, remainder = divmod(remainder, 3600)
    m, s = divmod(remainder, 60)
    return f"{int(d)} 天 {int(h)} 小时 {int(m)} 分 {s:.1f} 秒"


def validate_name(name):
    """验证名称是否合法（适合用作符号名）。"""
    if not name or not isinstance(name, str):
        return False
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
        return False
    if len(name) < 2 or len(name) > 128:
        return False
    if name.lower() in C_KEYWORDS:
        return False
    return True


# ─────────────────────────────────────────────────────────────
#  函数匹配与查询
# ─────────────────────────────────────────────────────────────

def match_functions(pattern):
    """按函数名或通配符模式匹配函数，返回 func_t 列表。"""
    log(f"[*] 正在匹配函数模式 '{pattern}'...\n")

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, pattern)
    if ea != ida_idaapi.BADADDR:
        func = ida_funcs.get_func(ea)
        if func:
            log(f"[+] 精确匹配: {pattern} -> 0x{ea:08X}\n")
            return [func]
        log(f"[!] 地址 0x{ea:X} 不属于任何函数\n")

    matched = []
    for fea in idautils.Functions():
        name = ida_funcs.get_func_name(fea)
        if fnmatch.fnmatch(name, pattern):
            func = ida_funcs.get_func(fea)
            if func:
                matched.append(func)
                if len(matched) >= MAX_MATCHES:
                    log(
                        f"[!] 匹配结果超过 {MAX_MATCHES}，已截断。"
                        f"请使用更精确的模式\n"
                    )
                    break

    if matched:
        log(f"[+] 通配符匹配找到 {len(matched)} 个函数\n")
    return matched


def is_auto_generated_name(name):
    """判断名称是否为 IDA 自动生成（sub_、dword_ 等前缀）。"""
    return any(name.startswith(p) for p in AUTO_NAME_PREFIXES)


def is_binary_symbol(ea):
    """判断地址处的名称是否来自二进制符号表（public symbol）。"""
    return ida_name.is_public_name(ea)


def decompile_function(func):
    """反编译函数，返回 cfunc_t 对象；失败或无反编译器时返回 None。"""
    if not _HAS_DECOMPILER:
        return None
    try:
        return ida_hexrays.decompile(func.start_ea)
    except Exception:
        return None


def generate_disassembly(func):
    """生成函数的完整反汇编文本（包括所有尾块）。"""
    lines = []
    for chunk in ida_funcs.func_tail_iterator_t(func):
        is_main = chunk.start_ea == func.start_ea
        if not is_main:
            lines.append(
                f"; --- 尾块: 0x{chunk.start_ea:08X} - "
                f"0x{chunk.end_ea:08X} ---"
            )
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            disasm = ida_lines.generate_disasm_line(
                ea, ida_lines.GENDSM_REMOVE_TAGS
            )
            lines.append(f"0x{ea:08X}    {disasm}")
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return "\n".join(lines)


def get_callers(ea):
    """获取调用指定地址的所有函数，返回格式化字符串列表。"""
    callers = []
    xb = ida_xref.xrefblk_t()
    for ref in xb.crefs_to(ea):
        name = ida_funcs.get_func_name(ref)
        callers.append(
            f"{name} (0x{ref:X})" if name else f"0x{ref:X}"
        )
    return callers[:MAX_REFS_DISPLAY]


def get_callees(func):
    """获取函数调用的所有其他函数，返回格式化字符串列表。"""
    callees = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for ref in idautils.CodeRefsFrom(ea, 0):
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea != func.start_ea:
                    name = ida_funcs.get_func_name(callee.start_ea)
                    callees.add(f"{name} (0x{callee.start_ea:X})")
                if len(callees) >= MAX_REFS_DISPLAY:
                    break
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return sorted(callees)


def get_auto_named_callee_funcs(func):
    """获取函数调用的所有自动命名函数（sub_XXXXX），返回 func_t 列表。"""
    callees = []
    seen = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for ref in idautils.CodeRefsFrom(ea, 0):
                callee = ida_funcs.get_func(ref)
                if (
                    callee
                    and callee.start_ea != func.start_ea
                    and callee.start_ea not in seen
                ):
                    seen.add(callee.start_ea)
                    name = ida_funcs.get_func_name(callee.start_ea)
                    if is_auto_generated_name(name):
                        callees.append(callee)
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return callees


def get_referenced_strings(func):
    """获取函数中引用的所有字符串常量。"""
    strings = []
    seen = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for ref in idautils.DataRefsFrom(ea):
                if ref in seen:
                    continue
                seen.add(ref)
                s = ida_bytes.get_strlit_contents(
                    ref, -1, ida_nalt.STRTYPE_C
                )
                if s:
                    strings.append(s.decode("utf-8", errors="replace"))
                    if len(strings) >= MAX_STRINGS_DISPLAY:
                        return strings
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return strings


# ─────────────────────────────────────────────────────────────
#  符号提取
# ─────────────────────────────────────────────────────────────

def is_auto_local_var_name(name):
    """判断局部变量名是否为自动生成（v1、v2 等格式）。"""
    return bool(re.match(r"^v\d+$", name))


def extract_local_vars(cfunc):
    """从反编译结果中提取所有自动命名的局部变量。"""
    if cfunc is None:
        return []
    result = []
    for lv in cfunc.lvars:
        if is_auto_local_var_name(lv.name):
            result.append(lv.name)
    return sorted(result, key=lambda n: int(n[1:]))


def extract_called_functions_from_source(source):
    """从反编译源码中提取所有 sub_ 开头的函数调用。"""
    funcs = set()
    for m in re.finditer(r"\b(sub_[0-9A-Fa-f]+)\b", source):
        funcs.add(m.group(1))
    return sorted(funcs)


def extract_global_data_from_source(source):
    """从反编译源码中提取所有自动命名的全局数据引用。"""
    data = set()
    for m in re.finditer(
        r"\b(dword|qword|word|byte|off|unk|asc)_[0-9A-Fa-f]+\b", source
    ):
        data.add(m.group(0))
    return sorted(data)


def extract_struct_fields(cfunc):
    """从反编译结果中提取所有自动命名的结构体字段。

    返回 dict: {结构体名: [字段名列表]}
    """
    if cfunc is None:
        return {}
    struct_fields = {}
    for lv in cfunc.lvars:
        tif = lv.type()
        if tif is None:
            continue
        target = tif
        if tif.is_ptr():
            target = tif.get_pointed_object()
            if target is None:
                continue
        if not target.is_struct():
            continue
        struct_name = target.get_type_name()
        if not struct_name:
            continue
        udt = ida_typeinf.udt_type_data_t()
        if not target.get_udt_details(udt):
            continue
        for udm in udt:
            if re.match(r"^field_[0-9A-Fa-f]+$", udm.name):
                if struct_name not in struct_fields:
                    struct_fields[struct_name] = []
                if udm.name not in struct_fields[struct_name]:
                    struct_fields[struct_name].append(udm.name)
    for struct_name in struct_fields:
        struct_fields[struct_name].sort()
    return struct_fields


def extract_all_symbols(func, cfunc, source):
    """提取函数中所有可重命名的符号。"""
    local_vars = extract_local_vars(cfunc)
    called_funcs = extract_called_functions_from_source(source)
    global_data = extract_global_data_from_source(source)
    struct_fields = extract_struct_fields(cfunc)

    total = (
        len(local_vars) + len(called_funcs) + len(global_data)
        + sum(len(v) for v in struct_fields.values())
    )
    log(
        f"[*] 提取到 {total} 个可重命名符号: "
        f"局部变量 {len(local_vars)} 个, "
        f"函数 {len(called_funcs)} 个, "
        f"全局数据 {len(global_data)} 个, "
        f"结构体字段 {sum(len(v) for v in struct_fields.values())} 个 "
        f"({len(struct_fields)} 个结构体)\n"
    )
    return {
        "local_vars": local_vars,
        "called_functions": called_funcs,
        "global_data": global_data,
        "struct_fields": struct_fields,
    }


def count_symbols(symbols):
    """计算符号字典中的符号总数。"""
    return (
        len(symbols["local_vars"])
        + len(symbols["called_functions"])
        + len(symbols["global_data"])
        + sum(len(v) for v in symbols["struct_fields"].values())
    )


def collect_function_context(func):
    """收集函数的完整上下文信息（反编译/反汇编、调用关系、字符串等）。

    返回 (context_dict, cfunc_or_None, source_string)。
    """
    func_name = ida_funcs.get_func_name(func.start_ea)
    context = {
        "name": func_name,
        "addr": func.start_ea,
        "size": func.size(),
        "callers": get_callers(func.start_ea),
        "callees": get_callees(func),
        "strings": get_referenced_strings(func),
    }

    cfunc = decompile_function(func)
    if cfunc:
        source = str(cfunc)
        context["source"] = source
        context["source_type"] = "decompiled"
        log(f"  [+] 反编译成功 ({len(source.splitlines())} 行)\n")
    else:
        source = generate_disassembly(func)
        context["source"] = source
        context["source_type"] = "disassembly"
        log(
            f"  [*] 反编译不可用，使用反汇编 "
            f"({len(source.splitlines())} 行)\n"
        )
        cfunc = None

    return context, cfunc, source


# ─────────────────────────────────────────────────────────────
#  AI 调用
# ─────────────────────────────────────────────────────────────

def call_ai(prompt):
    """调用 AI（通过 opencode CLI）分析提示词，返回结构化结果字典。"""
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    try:
        from ai.opencode import run_opencode
    except ImportError:
        log(
            "[!] 无法导入 ai.opencode 模块，"
            "请确认项目根目录在 sys.path 中\n"
        )
        return None

    return run_opencode(prompt)


def parse_ai_response(response_text):
    """解析 AI 返回的文本，提取其中的 JSON 对象。"""
    if not response_text:
        return None

    text = response_text.strip()

    code_block = re.search(
        r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL
    )
    if code_block:
        text = code_block.group(1).strip()

    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    brace_count = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if brace_count == 0:
                start = i
            brace_count += 1
        elif c == "}":
            brace_count -= 1
            if brace_count == 0 and start >= 0:
                candidate = text[start : i + 1]
                try:
                    result = json.loads(candidate)
                    if isinstance(result, dict):
                        return result
                except json.JSONDecodeError:
                    pass

    return None


# ─────────────────────────────────────────────────────────────
#  函数迭代框架
# ─────────────────────────────────────────────────────────────

def process_functions(pattern, processor, recursive=False,
                      max_depth=DEFAULT_MAX_DEPTH, command_label=""):
    """通用函数处理框架：BFS 遍历 + 日志 + 统计。

    processor 签名: processor(func, depth, idx) -> (success_count, fail_count)

    返回 (total_success, total_fail, total_functions)。
    """
    matched = match_functions(pattern)
    if not matched:
        log(f"[!] 未找到匹配 '{pattern}' 的函数\n")
        return 0, 0, 0

    queue = [(func, 0) for func in matched]
    visited = set()
    total = 0
    total_success = 0
    total_fail = 0

    while queue:
        func, depth = queue.pop(0)

        if func.start_ea in visited:
            continue
        visited.add(func.start_ea)

        total += 1
        func_name = ida_funcs.get_func_name(func.start_ea)
        depth_label = f" (递归深度 {depth})" if depth > 0 else ""
        log(
            f"\n[*] ========== [{total}] "
            f"{func_name} (0x{func.start_ea:08X}){depth_label} "
            f"==========\n"
        )

        s, f_ = processor(func, depth, total)
        total_success += s
        total_fail += f_

        if recursive and depth < max_depth:
            callee_funcs = get_auto_named_callee_funcs(func)
            if callee_funcs:
                log(
                    f"[*] 发现 {len(callee_funcs)} 个自动命名的被调用函数"
                    f"，加入分析队列 (深度 {depth + 1})\n"
                )
                for callee in callee_funcs:
                    if callee.start_ea not in visited:
                        queue.append((callee, depth + 1))
            else:
                log(
                    f"[*] 未发现自动命名的被调用函数"
                    f"，递归到此结束 (当前深度 {depth}/{max_depth})\n"
                )

    log(f"\n[+] ========== {command_label}完成 ==========\n")
    log(
        f"[+] 总计: {total} 个函数 | "
        f"成功: {total_success} | 失败: {total_fail}\n"
    )

    return total_success, total_fail, total
