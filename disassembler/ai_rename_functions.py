# -*- coding: utf-8 -*-
"""summary: AI 辅助符号重命名（函数、局部变量、全局数据、结构体字段）

description:
  使用 AI 分析函数及其内部引用的所有符号，自动将自动生成名称
  （sub_XXXXX、v1、dword_XXXXX、field_0 等）重命名为有意义的名称。
  支持精确函数名和通配符模式匹配（如 sub_123*），可批量处理。

  递归模式（--recursive）：分析完目标函数后，自动继续分析其调用的所有
  自动命名函数（sub_XXXXX），实现级联重命名。

  对话框模式（IDA GUI 内，无参数）：
    exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())

  IDA GUI 内 CLI 模式（通过 sys.argv 传参）：
    import sys
    sys.argv = ["", "--use-mode", "cli", "--pattern", "main_0", "--recursive"]
    exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())

  编程方式调用（IDA GUI 内）：
    exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())
    rename_functions("main_0", dry_run=False, recursive=True)

  命令行 headless 模式（通过 idat -A -S 调用，用环境变量传参）：
    IDA_PATTERN="main_0" IDA_RECURSIVE=1 \
      idat -A -S"disassembler/ai_rename_functions.py" binary.i64

  --dry-run / IDA_DRY_RUN: 仅预览 AI 建议的名称，不实际执行重命名。
  --recursive / IDA_RECURSIVE: 递归分析目标函数调用的自动命名函数。
  --max-depth / IDA_MAX_DEPTH: 递归最大深度，默认 2。

  重命名范围：
    - 函数名（sub_XXXXX）
    - 局部变量（v1、v2 等）通过 Hex-Rays modify_user_lvars API
    - 全局数据（dword_XXXXX、qword_XXXXX、off_XXXXX 等）
    - 结构体字段（field_0、field_4 等）通过 tinfo_t.rename_udm API

level: advanced
"""

import fnmatch
import json
import os
import re
import sys
import time

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


_AUTO_NAME_PREFIXES = (
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
_MAX_MATCHES = 100
_MAX_SOURCE_LINES = 400
_MAX_REFS_DISPLAY = 20
_MAX_STRINGS_DISPLAY = 20
_MAX_SYMBOLS_PER_PROMPT = 50
_DEFAULT_MAX_DEPTH = 2

_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex",
    "_Imaginary",
})


# ─────────────────────────────────────────────────────────────
#  函数匹配
# ─────────────────────────────────────────────────────────────

def _match_functions(pattern):
    ida_kernwin.msg(f"[*] 正在匹配函数模式 '{pattern}'...\n")

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, pattern)
    if ea != ida_idaapi.BADADDR:
        func = ida_funcs.get_func(ea)
        if func:
            ida_kernwin.msg(f"[+] 精确匹配: {pattern} -> 0x{ea:08X}\n")
            return [func]
        ida_kernwin.msg(f"[!] 地址 0x{ea:X} 不属于任何函数\n")

    matched = []
    for fea in idautils.Functions():
        name = ida_funcs.get_func_name(fea)
        if fnmatch.fnmatch(name, pattern):
            func = ida_funcs.get_func(fea)
            if func:
                matched.append(func)
                if len(matched) >= _MAX_MATCHES:
                    ida_kernwin.msg(
                        f"[!] 匹配结果超过 {_MAX_MATCHES}，已截断。"
                        f"请使用更精确的模式\n"
                    )
                    break

    if matched:
        ida_kernwin.msg(f"[+] 通配符匹配找到 {len(matched)} 个函数\n")
    return matched


def _is_auto_generated_name(name):
    return any(name.startswith(p) for p in _AUTO_NAME_PREFIXES)


# ─────────────────────────────────────────────────────────────
#  上下文收集
# ─────────────────────────────────────────────────────────────

def _decompile_function(func):
    if not _HAS_DECOMPILER:
        return None
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        return cfunc
    except Exception:
        return None


def _generate_disassembly(func):
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


def _get_callers(ea):
    callers = []
    xb = ida_xref.xrefblk_t()
    for ref in xb.crefs_to(ea):
        name = ida_funcs.get_func_name(ref)
        callers.append(
            f"{name} (0x{ref:X})" if name else f"0x{ref:X}"
        )
    return callers[:_MAX_REFS_DISPLAY]


def _get_callees(func):
    callees = set()
    for chunk in ida_funcs.func_tail_iterator_t(func):
        ea = chunk.start_ea
        while ea < chunk.end_ea and ea != ida_idaapi.BADADDR:
            for ref in idautils.CodeRefsFrom(ea, 0):
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea != func.start_ea:
                    name = ida_funcs.get_func_name(callee.start_ea)
                    callees.add(f"{name} (0x{callee.start_ea:X})")
                if len(callees) >= _MAX_REFS_DISPLAY:
                    break
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return sorted(callees)


def _get_auto_named_callee_funcs(func):
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
                    if _is_auto_generated_name(name):
                        callees.append(callee)
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return callees


def _get_referenced_strings(func):
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
                    if len(strings) >= _MAX_STRINGS_DISPLAY:
                        return strings
            ea = ida_bytes.next_head(ea, chunk.end_ea)
            if ea == ida_idaapi.BADADDR:
                break
    return strings


# ─────────────────────────────────────────────────────────────
#  符号提取：从反编译代码中提取所有可重命名的符号
# ─────────────────────────────────────────────────────────────

def _is_auto_local_var_name(name):
    return bool(re.match(r"^v\d+$", name))


def _extract_local_vars(cfunc):
    if cfunc is None:
        return []
    result = []
    for lv in cfunc.lvars:
        if _is_auto_local_var_name(lv.name):
            result.append(lv.name)
    return sorted(result, key=lambda n: int(n[1:]))


def _extract_called_functions_from_source(source):
    funcs = set()
    for m in re.finditer(r"\b(sub_[0-9A-Fa-f]+)\b", source):
        funcs.add(m.group(1))
    return sorted(funcs)


def _extract_global_data_from_source(source):
    data = set()
    for m in re.finditer(
        r"\b(dword|qword|word|byte|off|unk|asc)_[0-9A-Fa-f]+\b", source
    ):
        data.add(m.group(0))
    return sorted(data)


def _extract_struct_fields(cfunc):
    if cfunc is None:
        return {}
    til = ida_typeinf.get_idati()
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


def _extract_all_symbols(func, cfunc, source):
    local_vars = _extract_local_vars(cfunc)
    called_funcs = _extract_called_functions_from_source(source)
    global_data = _extract_global_data_from_source(source)
    struct_fields = _extract_struct_fields(cfunc)

    total = (
        len(local_vars) + len(called_funcs) + len(global_data)
        + sum(len(v) for v in struct_fields.values())
    )
    ida_kernwin.msg(
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


# ─────────────────────────────────────────────────────────────
#  AI 集成
# ─────────────────────────────────────────────────────────────

def _build_comprehensive_prompt(func_name, context, symbols):
    sections = []

    sections.append(
        "你是一位资深的逆向工程专家。"
        "请分析以下反编译代码，为函数本身和其中所有自动命名的符号建议有意义的名称。\n"
    )

    sections.append("## 函数信息")
    sections.append(f"- 当前名称: {func_name}")
    sections.append(f"- 地址: 0x{context['addr']:08X}")
    sections.append(f"- 大小: {context['size']} 字节\n")

    if context["callers"]:
        sections.append("## 调用者（谁调用了此函数）")
        for c in context["callers"]:
            sections.append(f"- {c}")
        sections.append("")

    if context["callees"]:
        sections.append("## 被调用函数（此函数调用了谁）")
        for c in context["callees"]:
            sections.append(f"- {c}")
        sections.append("")

    if context["strings"]:
        sections.append("## 引用的字符串")
        for s in context["strings"]:
            sections.append(f'- "{s}"')
        sections.append("")

    sections.append("## 反编译伪代码")
    source_lines = context["source"].splitlines()
    total_lines = len(source_lines)
    if total_lines > _MAX_SOURCE_LINES:
        source_lines = source_lines[:_MAX_SOURCE_LINES]
        source_lines.append(f"... (已截断，共 {total_lines} 行)")
    sections.append("```c")
    sections.extend(source_lines)
    sections.append("```\n")

    sections.append("## 待重命名的符号列表")

    if symbols["local_vars"]:
        sections.append("### 局部变量（v1、v2 等自动编号的变量）")
        for v in symbols["local_vars"]:
            sections.append(f"- {v}")
        sections.append("")

    if symbols["called_functions"]:
        sections.append("### 调用的函数（sub_XXXXX 等自动命名的函数）")
        for f in symbols["called_functions"]:
            sections.append(f"- {f}")
        sections.append("")

    if symbols["global_data"]:
        sections.append("### 全局数据引用（dword_XXXXX 等自动命名的数据）")
        for d in symbols["global_data"]:
            sections.append(f"- {d}")
        sections.append("")

    if symbols["struct_fields"]:
        sections.append("### 结构体字段（field_0 等自动命名的字段）")
        for sname, fields in symbols["struct_fields"].items():
            for f in fields:
                sections.append(f"- {sname}.{f}")
        sections.append("")

    sections.append("## 命名规则")
    sections.append("1. 使用 snake_case 风格（小写字母 + 下划线）")
    sections.append(
        "2. 函数名以动词开头（如 parse_、validate_、decode_、init_ 等）"
    )
    sections.append(
        "3. 变量名应体现用途（如 username、password、buffer_size）"
    )
    sections.append(
        "4. 结构体字段名应体现语义（如 checksum、next_ptr、flags）"
    )
    sections.append(
        "5. 名称应准确反映实际功能，避免过于泛化"
    )
    sections.append("6. 仅使用小写英文字母、数字和下划线，以字母或下划线开头")
    sections.append("7. 不使用 C/C++ 关键字或标准库函数名\n")

    sections.append("## 输出格式")
    sections.append(
        '请严格按照以下 JSON 格式返回，不要添加任何其他内容：\n'
    )
    sections.append("```json")
    sections.append("{")
    sections.append('  "function": "新函数名",')
    sections.append('  "reasoning": "分析理由",')
    sections.append('  "confidence": "high/medium/low",')
    sections.append('  "symbols": {')
    sections.append('    "sub_140001234": "validate_password",')
    sections.append('    "v1": "username",')
    sections.append('    "v2": "password",')
    sections.append('    "dword_14000XXXX": "retry_count",')
    sections.append('    "MyStruct.field_4": "checksum"')
    sections.append("  }")
    sections.append("}")
    sections.append("```")
    sections.append("")
    sections.append(
        "symbols 中只包含你能确定用途的符号，不确定的不要包含。"
        "键名保持原始名称，结构体字段用 \"结构体名.字段名\" 格式。"
    )

    return "\n".join(sections)


def _call_ai(prompt):
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    try:
        from ai.opencode import run_opencode
    except ImportError:
        ida_kernwin.msg(
            "[!] 无法导入 ai.opencode 模块，"
            "请确认项目根目录在 sys.path 中\n"
        )
        return None

    return run_opencode(prompt)


def _parse_ai_response(response_text):
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


def _validate_name(name):
    if not name or not isinstance(name, str):
        return False
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
        return False
    if len(name) < 2 or len(name) > 128:
        return False
    if name.lower() in _C_KEYWORDS:
        return False
    return True


# ─────────────────────────────────────────────────────────────
#  重命名执行
# ─────────────────────────────────────────────────────────────

def _apply_function_rename(addr, old_name, new_name, dry_run=False):
    if dry_run:
        ida_kernwin.msg(
            f"  [预览-函数] {old_name} -> {new_name}\n"
        )
        return True

    success = ida_name.set_name(addr, new_name, ida_name.SN_NOWARN)
    if success:
        ida_kernwin.msg(
            f"  [+] 函数重命名: {old_name} (0x{addr:08X}) -> {new_name}\n"
        )
    else:
        ida_kernwin.msg(
            f"  [!] 函数重命名失败: {old_name} -> {new_name}\n"
        )
    return success


def _apply_local_var_rename(func_ea, old_name, new_name, dry_run=False):
    if dry_run:
        ida_kernwin.msg(
            f"  [预览-局部变量] {old_name} -> {new_name}\n"
        )
        return True

    if not _HAS_DECOMPILER:
        ida_kernwin.msg(
            f"  [!] 局部变量重命名需要 Hex-Rays 反编译器: {old_name}\n"
        )
        return False

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return False

    target_lvar = None
    for lv in cfunc.lvars:
        if lv.name == old_name:
            target_lvar = lv
            break

    if target_lvar is None:
        ida_kernwin.msg(
            f"  [!] 未找到局部变量: {old_name}\n"
        )
        return False

    class _Renamer(ida_hexrays.user_lvar_modifier_t):
        def __init__(self, lvar_obj, new_n):
            ida_hexrays.user_lvar_modifier_t.__init__(self)
            self._lvar = lvar_obj
            self._new_name = new_n
            self._found = False

        def modify_lvars(self, lvars):
            for lv in lvars.lvvec:
                if lv.ll.defea == self._lvar.defea:
                    lv.name = self._new_name
                    self._found = True
                    return True
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = self._lvar
            lsi.name = self._new_name
            lvars.lvvec.push_back(lsi)
            self._found = True
            return True

    renamer = _Renamer(target_lvar, new_name)
    success = ida_hexrays.modify_user_lvars(func_ea, renamer)

    if success and renamer._found:
        ida_kernwin.msg(
            f"  [+] 局部变量重命名: {old_name} -> {new_name}\n"
        )
    else:
        ida_kernwin.msg(
            f"  [!] 局部变量重命名失败: {old_name} -> {new_name}\n"
        )
    return success and renamer._found


def _apply_global_data_rename(name_str, new_name, dry_run=False):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name_str)
    if ea == ida_idaapi.BADADDR:
        ida_kernwin.msg(
            f"  [!] 全局数据地址未找到: {name_str}\n"
        )
        return False

    if dry_run:
        ida_kernwin.msg(
            f"  [预览-全局数据] {name_str} (0x{ea:08X}) -> {new_name}\n"
        )
        return True

    success = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN)
    if success:
        ida_kernwin.msg(
            f"  [+] 全局数据重命名: {name_str} (0x{ea:08X}) -> {new_name}\n"
        )
    else:
        ida_kernwin.msg(
            f"  [!] 全局数据重命名失败: {name_str} -> {new_name}\n"
        )
    return success


def _apply_struct_field_rename(struct_name, field_name, new_name,
                               dry_run=False):
    if dry_run:
        ida_kernwin.msg(
            f"  [预览-结构体字段] {struct_name}.{field_name} -> "
            f"{struct_name}.{new_name}\n"
        )
        return True

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, struct_name):
        ida_kernwin.msg(
            f"  [!] 结构体类型未找到: {struct_name}\n"
        )
        return False

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        ida_kernwin.msg(
            f"  [!] 无法获取结构体详情: {struct_name}\n"
        )
        return False

    idx, found_udm = tif.get_udm(field_name)
    if not found_udm:
        ida_kernwin.msg(
            f"  [!] 结构体 {struct_name} 中未找到字段: {field_name}\n"
        )
        return False

    result = tif.rename_udm(idx, new_name)
    if result == ida_typeinf.TERR_OK:
        ida_kernwin.msg(
            f"  [+] 结构体字段重命名: {struct_name}.{field_name} -> "
            f"{struct_name}.{new_name}\n"
        )
        return True

    ida_kernwin.msg(
        f"  [!] 结构体字段重命名失败: {struct_name}.{field_name} "
        f"(错误码: {result})\n"
    )
    return False


def _apply_all_renames(func, ai_result, symbols, dry_run=False):
    func_name = ida_funcs.get_func_name(func.start_ea)
    func_rename = ai_result.get("function", "")
    symbol_map = ai_result.get("symbols", {})
    reasoning = ai_result.get("reasoning", "")
    confidence = ai_result.get("confidence", "low")

    confidence_label = (
        {"high": "高", "medium": "中", "low": "低"}
        .get(confidence, str(confidence))
    )

    ida_kernwin.msg(
        f"[*] AI 分析结果 (置信度: {confidence_label}):\n"
    )
    ida_kernwin.msg(f"[*] 理由: {reasoning}\n")

    total_success = 0
    total_fail = 0

    if func_rename and _validate_name(func_rename):
        ida_kernwin.msg(
            f"[*] 函数重命名: {func_name} -> {func_rename}\n"
        )
        if _apply_function_rename(
            func.start_ea, func_name, func_rename, dry_run
        ):
            total_success += 1
            if not dry_run:
                comment = (
                    f"AI 重命名 | 原名: {func_name} | "
                    f"理由: {reasoning} | 置信度: {confidence_label}"
                )
                ida_bytes.set_cmt(func.start_ea, comment, 0)
        else:
            total_fail += 1
    elif func_rename:
        ida_kernwin.msg(
            f"[!] AI 建议的函数名 '{func_rename}' 不合法，跳过\n"
        )
        total_fail += 1

    for symbol_key, suggested_name in symbol_map.items():
        if not _validate_name(suggested_name):
            ida_kernwin.msg(
                f"  [!] 建议名称 '{suggested_name}' 不合法，"
                f"跳过 {symbol_key}\n"
            )
            total_fail += 1
            continue

        if symbol_key in symbols["local_vars"]:
            if _apply_local_var_rename(
                func.start_ea, symbol_key, suggested_name, dry_run
            ):
                total_success += 1
            else:
                total_fail += 1

        elif symbol_key in symbols["called_functions"]:
            if _apply_function_rename_by_name(
                symbol_key, suggested_name, dry_run
            ):
                total_success += 1
            else:
                total_fail += 1

        elif symbol_key in symbols["global_data"]:
            if _apply_global_data_rename(
                symbol_key, suggested_name, dry_run
            ):
                total_success += 1
            else:
                total_fail += 1

        elif "." in symbol_key:
            parts = symbol_key.split(".", 1)
            if len(parts) == 2:
                sname, fname = parts
                if (
                    sname in symbols["struct_fields"]
                    and fname in symbols["struct_fields"][sname]
                ):
                    if _apply_struct_field_rename(
                        sname, fname, suggested_name, dry_run
                    ):
                        total_success += 1
                    else:
                        total_fail += 1
                else:
                    ida_kernwin.msg(
                        f"  [!] 未识别的符号键: {symbol_key}\n"
                    )
                    total_fail += 1

    return total_success, total_fail


def _apply_function_rename_by_name(old_name, new_name, dry_run=False):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, old_name)
    if ea == ida_idaapi.BADADDR:
        ida_kernwin.msg(
            f"  [!] 函数地址未找到: {old_name}\n"
        )
        return False
    return _apply_function_rename(ea, old_name, new_name, dry_run)


# ─────────────────────────────────────────────────────────────
#  主流程
# ─────────────────────────────────────────────────────────────

def _format_elapsed(seconds):
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


def _analyze_function(func, dry_run=False):
    func_name = ida_funcs.get_func_name(func.start_ea)
    context = {
        "name": func_name,
        "addr": func.start_ea,
        "size": func.size(),
        "callers": _get_callers(func.start_ea),
        "callees": _get_callees(func),
        "strings": _get_referenced_strings(func),
    }

    cfunc = _decompile_function(func)
    if cfunc:
        source = str(cfunc)
        context["source"] = source
        context["source_type"] = "decompiled"
        ida_kernwin.msg(
            f"  [+] 反编译成功 ({len(source.splitlines())} 行)\n"
        )
    else:
        source = _generate_disassembly(func)
        context["source"] = source
        context["source_type"] = "disassembly"
        ida_kernwin.msg(
            f"  [*] 反编译不可用，使用反汇编 "
            f"({len(source.splitlines())} 行)\n"
        )
        cfunc = None

    symbols = _extract_all_symbols(func, cfunc, source)
    total_symbols = (
        len(symbols["local_vars"]) + len(symbols["called_functions"])
        + len(symbols["global_data"])
        + sum(len(v) for v in symbols["struct_fields"].values())
    )

    if total_symbols == 0:
        ida_kernwin.msg(f"  [*] 无可重命名的符号，跳过 AI 分析\n")
        return 0, 0

    ida_kernwin.msg(f"[*] 正在调用 AI 分析 ({total_symbols} 个符号)...\n")
    prompt = _build_comprehensive_prompt(func_name, context, symbols)

    start_time = time.time()
    result = _call_ai(prompt)
    elapsed = time.time() - start_time

    if result is None:
        ida_kernwin.msg(
            f"[!] AI 调用失败 (耗时 {_format_elapsed(elapsed)})\n"
        )
        return 0, 1

    if not result["success"]:
        ida_kernwin.msg(
            f"[!] AI 分析失败 (耗时 {_format_elapsed(elapsed)}): "
            f"{result['message']}\n"
        )
        return 0, 1

    ida_kernwin.msg(
        f"[+] AI 分析完成 (耗时 {_format_elapsed(elapsed)})\n"
    )

    parsed = _parse_ai_response(result["message"])
    if parsed is None:
        ida_kernwin.msg("[!] 无法解析 AI 响应为 JSON\n")
        raw_preview = result["message"][:300]
        ida_kernwin.msg(f"[*] AI 原始响应: {raw_preview}\n")
        return 0, 1

    return _apply_all_renames(func, parsed, symbols, dry_run)


def rename_functions(pattern, dry_run=False, recursive=False,
                     max_depth=_DEFAULT_MAX_DEPTH):
    ida_kernwin.msg(
        f"[*] 开始 AI 辅助符号重命名: pattern='{pattern}', "
        f"dry_run={dry_run}, recursive={recursive}, "
        f"max_depth={max_depth}\n"
    )

    matched = _match_functions(pattern)
    if not matched:
        ida_kernwin.msg(f"[!] 未找到匹配 '{pattern}' 的函数\n")
        return False

    queue = [(func, 0) for func in matched]
    visited = set()
    success_count = 0
    fail_count = 0
    total = 0

    while queue:
        func, depth = queue.pop(0)

        if func.start_ea in visited:
            continue
        visited.add(func.start_ea)

        total += 1
        func_name = ida_funcs.get_func_name(func.start_ea)
        depth_label = f" (递归深度 {depth})" if depth > 0 else ""
        ida_kernwin.msg(
            f"\n[*] ========== [{total}] "
            f"{func_name} (0x{func.start_ea:08X}){depth_label} "
            f"==========\n"
        )

        s, f_ = _analyze_function(func, dry_run)
        success_count += s
        fail_count += f_

        if recursive and depth < max_depth:
            callee_funcs = _get_auto_named_callee_funcs(func)
            if callee_funcs:
                ida_kernwin.msg(
                    f"[*] 发现 {len(callee_funcs)} 个自动命名的被调用函数"
                    f"，加入分析队列 (深度 {depth + 1})\n"
                )
                for callee in callee_funcs:
                    if callee.start_ea not in visited:
                        queue.append((callee, depth + 1))

    ida_kernwin.msg("\n[+] ========== 重命名完成 ==========\n")
    ida_kernwin.msg(
        f"[+] 总计: {total} 个函数 | "
        f"成功: {success_count} | 失败: {fail_count}\n"
    )

    return success_count > 0


# ─────────────────────────────────────────────────────────────
#  对话框模式
# ─────────────────────────────────────────────────────────────

class _RenameForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* 分析并重命名
BUTTON CANCEL 取消
AI 辅助符号重命名

<##函数名或通配符模式 (如 sub_123* 或 main) :{pattern}>
<{recursive}>递归分析被调用的自动命名函数>
<##递归最大深度 (默认 2):{max_depth}>
<{dry_run}>仅预览（不实际重命名）>
""",
            {
                "pattern": F.StringInput(),
                "recursive": F.BoolInput(),
                "max_depth": F.StringInput(),
                "dry_run": F.BoolInput(),
            },
        )


def show_dialog():
    f = _RenameForm()
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        pattern = (f.pattern.value or "").strip()
        recursive = bool(f.recursive.value)
        max_depth_str = (f.max_depth.value or "").strip()
        dry_run = bool(f.dry_run.value)
        try:
            max_depth = int(max_depth_str) if max_depth_str else _DEFAULT_MAX_DEPTH
        except ValueError:
            max_depth = _DEFAULT_MAX_DEPTH
        if pattern:
            ida_kernwin.msg("[*] 对话框模式: 用户确认分析\n")
            rename_functions(
                pattern, dry_run=dry_run,
                recursive=recursive, max_depth=max_depth,
            )
        else:
            ida_kernwin.msg("[!] 已取消: 函数名或模式不能为空\n")
    else:
        ida_kernwin.msg("[*] 对话框模式: 用户取消操作\n")
    f.Free()


# ─────────────────────────────────────────────────────────────
#  CLI 模式
# ─────────────────────────────────────────────────────────────

def _parse_cli_argv(argv):
    args = argv[1:]
    if len(args) < 4:
        return None

    try:
        use_mode_idx = args.index("--use-mode")
    except ValueError:
        return None

    if use_mode_idx + 1 >= len(args) or args[use_mode_idx + 1] != "cli":
        return None

    try:
        pattern_idx = args.index("--pattern")
    except ValueError:
        return None

    if pattern_idx + 1 >= len(args) or args[pattern_idx + 1].startswith("--"):
        return None

    dry_run = "--dry-run" in args
    recursive = "--recursive" in args

    max_depth = _DEFAULT_MAX_DEPTH
    try:
        depth_idx = args.index("--max-depth")
        if depth_idx + 1 < len(args):
            max_depth = int(args[depth_idx + 1])
    except (ValueError, IndexError):
        pass

    return args[pattern_idx + 1], dry_run, recursive, max_depth


# ─────────────────────────────────────────────────────────────
#  Headless 模式
# ─────────────────────────────────────────────────────────────

def _parse_env_args():
    pattern = os.environ.get("IDA_PATTERN", "").strip()
    dry_run = bool(os.environ.get("IDA_DRY_RUN", "").strip())
    recursive = bool(os.environ.get("IDA_RECURSIVE", "").strip())
    try:
        max_depth = int(os.environ.get("IDA_MAX_DEPTH", "").strip())
    except (ValueError, AttributeError):
        max_depth = _DEFAULT_MAX_DEPTH
    ida_kernwin.msg(
        f"[*] 环境变量: IDA_PATTERN='{pattern}', "
        f"IDA_DRY_RUN='{dry_run}', IDA_RECURSIVE='{recursive}', "
        f"IDA_MAX_DEPTH='{max_depth}'\n"
    )
    if pattern:
        return pattern, dry_run, recursive, max_depth
    return None


def _run_headless(pattern, dry_run=False, recursive=False,
                  max_depth=_DEFAULT_MAX_DEPTH):
    import ida_auto
    import ida_pro

    ida_kernwin.msg("[*] headless 模式: 等待 IDA 自动分析完成...\n")
    ida_auto.auto_wait()
    ida_kernwin.msg("[*] headless 模式: 自动分析完成，开始 AI 重命名\n")

    success = rename_functions(
        pattern, dry_run=dry_run,
        recursive=recursive, max_depth=max_depth,
    )

    exit_code = 0 if success else 1
    ida_kernwin.msg(
        f"[{'+'if success else '!'}] headless 模式: "
        f"重命名{'成功' if success else '失败'}，"
        f"正在退出 (exit code {exit_code})\n"
    )
    ida_pro.qexit(exit_code)


# ─────────────────────────────────────────────────────────────
#  模块级入口
# ─────────────────────────────────────────────────────────────

_batch = bool(ida_kernwin.cvar.batch)
_env = _parse_env_args()

if _batch and _env is not None:
    ida_kernwin.msg("[*] 检测到 headless 模式 (batch=True)，使用环境变量参数\n")
    _run_headless(
        _env[0], dry_run=_env[1],
        recursive=_env[2], max_depth=_env[3],
    )
elif _batch:
    ida_kernwin.msg("[!] headless 模式需要设置 IDA_PATTERN 环境变量\n")
    import ida_pro
    ida_pro.qexit(1)
elif __name__ == "__main__":
    has_args = len(sys.argv) > 1
    cli_result = _parse_cli_argv(sys.argv)
    sys.argv = sys.argv[:1]
    if cli_result is not None:
        ida_kernwin.msg("[*] CLI 模式: 使用命令行参数\n")
        rename_functions(
            cli_result[0], dry_run=cli_result[1],
            recursive=cli_result[2], max_depth=cli_result[3],
        )
    else:
        if has_args:
            ida_kernwin.msg(
                "[!] 参数格式错误，正确格式: "
                "--use-mode cli --pattern <函数名或模式> "
                "[--dry-run] [--recursive] [--max-depth <N>]\n"
            )
        ida_kernwin.msg("[*] 对话框模式: 等待用户输入\n")
        show_dialog()
