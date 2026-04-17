# -*- coding: utf-8 -*-
"""summary: AI 辅助符号重命名

description:
  使用 AI 分析函数及其内部引用的所有符号，自动将自动生成名称
  （sub_XXXXX、v1、dword_XXXXX、field_0 等）重命名为有意义的名称。

  重命名范围：
    - 函数名（sub_XXXXX）
    - 局部变量（v1、v2 等）通过 Hex-Rays modify_user_lvars API
    - 全局数据（dword_XXXXX、qword_XXXXX、off_XXXXX 等）
    - 结构体字段（field_0、field_4 等）通过 tinfo_t.rename_udm API

  本模块为内部模块，通过 ai_analyze.py 的 rename 子命令调用。
  当与 ai_comment.py 配合使用时（通过 ai_analyze.py 的 analyze 子命令），
  先执行重命名再生成注释，使注释基于重命名后的代码，提升注释质量。

  编程方式调用（IDA GUI 内，需先确保 disassembler/ 在 sys.path 中）：

    import ai_rename
    ai_rename.rename_functions("main_0", dry_run=False, recursive=True)

level: advanced
"""

import os
import sys
import time

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_typeinf

try:
    import ida_hexrays
except ImportError:
    pass

_script_dir = ""
try:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
except (NameError, TypeError):
    pass

if not _script_dir or not os.path.isdir(_script_dir):
    _script_dir = os.path.join(os.getcwd(), "disassembler")

if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

import ai_utils


class AIRenamer:
    """AI 辅助符号重命名（函数、局部变量、全局数据、结构体字段）。

    可独立使用，也可与 AICommenter 配合。
    当配合使用时，应先执行 AIRenamer.analyze()，再执行 AICommenter.analyze()，
    使注释基于重命名后的代码。
    """

    def __init__(self, func, context, cfunc, source, symbols):
        self.func = func
        self.func_name = ida_funcs.get_func_name(func.start_ea)
        self.context = context
        self.cfunc = cfunc
        self.source = source
        self.symbols = symbols
        self.last_details = []

    def _build_prompt(self):
        sections = []

        sections.append(
            "你是一位资深的逆向工程专家。"
            "请分析以下反编译代码，为函数本身和其中所有自动命名的符号"
            "建议有意义的名称。\n"
        )

        sections.append("## 函数信息")
        sections.append(f"- 当前名称: {self.func_name}")
        sections.append(f"- 地址: 0x{self.context['addr']:08X}")
        sections.append(f"- 大小: {self.context['size']} 字节\n")

        if self.context["callers"]:
            sections.append("## 调用者（谁调用了此函数）")
            for c in self.context["callers"]:
                sections.append(f"- {c}")
            sections.append("")

        if self.context["callees"]:
            sections.append("## 被调用函数（此函数调用了谁）")
            for c in self.context["callees"]:
                sections.append(f"- {c}")
            sections.append("")

        if self.context["strings"]:
            sections.append("## 引用的字符串")
            for s in self.context["strings"]:
                sections.append(f'- "{s}"')
            sections.append("")

        sections.append("## 反编译伪代码")
        source_lines = self.source.splitlines()
        total_lines = len(source_lines)
        if total_lines > ai_utils.MAX_SOURCE_LINES:
            source_lines = source_lines[:ai_utils.MAX_SOURCE_LINES]
            source_lines.append(f"... (已截断，共 {total_lines} 行)")
        sections.append("```c")
        sections.extend(source_lines)
        sections.append("```\n")

        sections.append("## 待重命名的符号列表")

        if self.symbols["local_vars"]:
            sections.append("### 局部变量（v1、v2 等自动编号的变量）")
            for v in self.symbols["local_vars"]:
                sections.append(f"- {v}")
            sections.append("")

        if self.symbols["called_functions"]:
            sections.append("### 调用的函数（sub_XXXXX 等自动命名的函数）")
            for f in self.symbols["called_functions"]:
                sections.append(f"- {f}")
            sections.append("")

        if self.symbols["global_data"]:
            sections.append("### 全局数据引用（dword_XXXXX 等自动命名的数据）")
            for d in self.symbols["global_data"]:
                sections.append(f"- {d}")
            sections.append("")

        if self.symbols["struct_fields"]:
            sections.append("### 结构体字段（field_0 等自动命名的字段）")
            for sname, fields in self.symbols["struct_fields"].items():
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
            "请严格按照以下 JSON 格式返回，不要添加任何其他内容：\n"
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

    def _apply_function_rename(self, addr, old_name, new_name, dry_run=False):
        if dry_run:
            ai_utils.log(f"  [预览-函数] {old_name} -> {new_name}\n")
            return True

        success = ida_name.set_name(addr, new_name, ida_name.SN_NOWARN)
        if success:
            ai_utils.log(
                f"  [+] 函数重命名: {old_name} (0x{addr:08X}) -> {new_name}\n"
            )
        else:
            ai_utils.log(f"  [!] 函数重命名失败: {old_name} -> {new_name}\n")
        return success

    def _apply_local_var_rename(self, old_name, new_name, dry_run=False):
        if dry_run:
            ai_utils.log(
                f"  [预览-局部变量] {old_name} -> {new_name}\n"
            )
            return True

        if not ai_utils._HAS_DECOMPILER:
            ai_utils.log(
                f"  [!] 局部变量重命名需要 Hex-Rays 反编译器: {old_name}\n"
            )
            return False

        cfunc = ida_hexrays.decompile(self.func.start_ea)
        if not cfunc:
            return False

        target_lvar = None
        for lv in cfunc.lvars:
            if lv.name == old_name:
                target_lvar = lv
                break

        if target_lvar is None:
            ai_utils.log(f"  [!] 未找到局部变量: {old_name}\n")
            return False

        class _LVarRenamer(ida_hexrays.user_lvar_modifier_t):
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

        renamer = _LVarRenamer(target_lvar, new_name)
        success = ida_hexrays.modify_user_lvars(self.func.start_ea, renamer)

        if success and renamer._found:
            ai_utils.log(
                f"  [+] 局部变量重命名: {old_name} -> {new_name}\n"
            )
        else:
            ai_utils.log(
                f"  [!] 局部变量重命名失败: {old_name} -> {new_name}\n"
            )
        return success and renamer._found

    def _apply_global_data_rename(self, name_str, new_name, dry_run=False):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name_str)
        if ea == ida_idaapi.BADADDR:
            ai_utils.log(f"  [!] 全局数据地址未找到: {name_str}\n")
            return False
        if ai_utils.is_binary_symbol(ea):
            ai_utils.log(
                f"  [!] 全局数据 '{name_str}' 来自二进制符号表，跳过重命名\n"
            )
            return False

        if dry_run:
            ai_utils.log(
                f"  [预览-全局数据] {name_str} (0x{ea:08X}) -> {new_name}\n"
            )
            return True

        success = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN)
        if success:
            ai_utils.log(
                f"  [+] 全局数据重命名: {name_str} (0x{ea:08X}) -> {new_name}\n"
            )
        else:
            ai_utils.log(
                f"  [!] 全局数据重命名失败: {name_str} -> {new_name}\n"
            )
        return success

    def _apply_struct_field_rename(self, struct_name, field_name,
                                   new_name, dry_run=False):
        if dry_run:
            ai_utils.log(
                f"  [预览-结构体字段] {struct_name}.{field_name} -> "
                f"{struct_name}.{new_name}\n"
            )
            return True

        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, struct_name):
            ai_utils.log(f"  [!] 结构体类型未找到: {struct_name}\n")
            return False

        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            ai_utils.log(f"  [!] 无法获取结构体详情: {struct_name}\n")
            return False

        idx, found_udm = tif.get_udm(field_name)
        if not found_udm:
            ai_utils.log(
                f"  [!] 结构体 {struct_name} 中未找到字段: {field_name}\n"
            )
            return False

        result = tif.rename_udm(idx, new_name)
        if result == ida_typeinf.TERR_OK:
            ai_utils.log(
                f"  [+] 结构体字段重命名: {struct_name}.{field_name} -> "
                f"{struct_name}.{new_name}\n"
            )
            return True

        ai_utils.log(
            f"  [!] 结构体字段重命名失败: {struct_name}.{field_name} "
            f"(错误码: {result})\n"
        )
        return False

    def _apply_function_rename_by_name(self, old_name, new_name,
                                       dry_run=False):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, old_name)
        if ea == ida_idaapi.BADADDR:
            ai_utils.log(f"  [!] 函数地址未找到: {old_name}\n")
            return False
        if ai_utils.is_binary_symbol(ea):
            ai_utils.log(
                f"  [!] 函数 '{old_name}' 来自二进制符号表，跳过重命名\n"
            )
            return False
        return self._apply_function_rename(ea, old_name, new_name, dry_run)

    def _apply_all(self, ai_result, dry_run=False):
        func_rename = ai_result.get("function", "")
        symbol_map = ai_result.get("symbols", {})
        reasoning = ai_result.get("reasoning", "")
        confidence = ai_result.get("confidence", "low")

        confidence_label = (
            {"high": "高", "medium": "中", "low": "低"}
            .get(confidence, str(confidence))
        )

        ai_utils.log(
            f"[*] AI 分析结果 (置信度: {confidence_label}):\n"
        )
        ai_utils.log(f"[*] 理由: {reasoning}\n")

        total_success = 0
        total_fail = 0
        self.last_details = []

        if func_rename and ai_utils.validate_name(func_rename):
            if ai_utils.is_binary_symbol(self.func.start_ea):
                ai_utils.log(
                    f"  [!] 函数 '{self.func_name}' 来自二进制符号表，"
                    f"跳过重命名（AI 建议: {func_rename}）\n"
                )
                self.last_details.append(ai_utils.RenameDetail(
                    type="函数", old=self.func_name,
                    new=func_rename, status="skipped_binary",
                ))
            elif not ai_utils.is_auto_generated_name(self.func_name):
                ai_utils.log(
                    f"  [!] 函数 '{self.func_name}' 可能是用户或调试符号定义的名称，"
                    f"跳过重命名（AI 建议: {func_rename}）\n"
                )
                self.last_details.append(ai_utils.RenameDetail(
                    type="函数", old=self.func_name,
                    new=func_rename, status="skipped_user",
                ))
            else:
                ai_utils.log(
                    f"[*] 函数重命名: {self.func_name} -> {func_rename}\n"
                )
                if self._apply_function_rename(
                    self.func.start_ea, self.func_name, func_rename, dry_run
                ):
                    total_success += 1
                    self.last_details.append(ai_utils.RenameDetail(
                        type="函数", old=self.func_name,
                        new=func_rename,
                        status="preview" if dry_run else "success",
                    ))
                    if not dry_run:
                        comment = (
                            f"AI 重命名 | 原名: {self.func_name} | "
                            f"理由: {reasoning} | 置信度: {confidence_label}"
                        )
                        ida_bytes.set_cmt(self.func.start_ea, comment, 0)
                else:
                    total_fail += 1
                    self.last_details.append(ai_utils.RenameDetail(
                        type="函数", old=self.func_name,
                        new=func_rename, status="failed",
                    ))
        elif func_rename:
            ai_utils.log(
                f"[!] AI 建议的函数名 '{func_rename}' 不合法，跳过\n"
            )
            total_fail += 1
            self.last_details.append(ai_utils.RenameDetail(
                type="函数", old=self.func_name,
                new=func_rename, status="invalid_name",
            ))

        for symbol_key, suggested_name in symbol_map.items():
            if not ai_utils.validate_name(suggested_name):
                ai_utils.log(
                    f"  [!] 建议名称 '{suggested_name}' 不合法，"
                    f"跳过 {symbol_key}\n"
                )
                total_fail += 1
                self.last_details.append(ai_utils.RenameDetail(
                    type="未知", old=symbol_key,
                    new=suggested_name, status="invalid_name",
                ))
                continue

            ok = False
            rename_type = "未知"

            if symbol_key in self.symbols["local_vars"]:
                rename_type = "局部变量"
                ok = self._apply_local_var_rename(
                    symbol_key, suggested_name, dry_run
                )
            elif symbol_key in self.symbols["called_functions"]:
                rename_type = "函数"
                ok = self._apply_function_rename_by_name(
                    symbol_key, suggested_name, dry_run
                )
            elif symbol_key in self.symbols["global_data"]:
                rename_type = "全局数据"
                ok = self._apply_global_data_rename(
                    symbol_key, suggested_name, dry_run
                )
            elif "." in symbol_key:
                parts = symbol_key.split(".", 1)
                if len(parts) == 2:
                    sname, fname = parts
                    if (
                        sname in self.symbols["struct_fields"]
                        and fname in self.symbols["struct_fields"][sname]
                    ):
                        rename_type = "结构体字段"
                        ok = self._apply_struct_field_rename(
                            sname, fname, suggested_name, dry_run
                        )
                    else:
                        ai_utils.log(
                            f"  [!] {self.func_name}: 未识别的符号键 '{symbol_key}'"
                            f"（结构体或字段不在提取列表中）\n"
                        )
                else:
                    ai_utils.log(
                        f"  [!] {self.func_name}: 未识别的符号键 '{symbol_key}'\n"
                    )
            else:
                ai_utils.log(
                    f"  [!] {self.func_name}: 未识别的符号键 '{symbol_key}'"
                    f"（不属于局部变量、函数、全局数据或结构体字段）\n"
                    )

            if ok:
                total_success += 1
                self.last_details.append(ai_utils.RenameDetail(
                    type=rename_type, old=symbol_key,
                    new=suggested_name,
                    status="preview" if dry_run else "success",
                ))
            else:
                reason = "未识别的符号键" if rename_type == "未知" else "重命名操作失败"
                total_fail += 1
                self.last_details.append(ai_utils.RenameDetail(
                    type=rename_type, old=symbol_key,
                    new=suggested_name, status="failed",
                    reason=reason,
                ))

        return total_success, total_fail

    def analyze(self, dry_run=False):
        """执行 AI 辅助重命名分析。

        返回 RenameResult。
        """
        symbol_count = ai_utils.count_symbols(self.symbols)
        ai_utils.log(
            f"[*] 正在调用 AI 分析重命名 ({symbol_count} 个符号)...\n"
        )
        prompt = self._build_prompt()

        start_time = time.time()
        result = ai_utils.call_ai(prompt)
        elapsed = time.time() - start_time

        if result is None:
            ai_utils.log(
                f"[!] AI 调用失败 (耗时 {ai_utils.format_elapsed(elapsed)})\n"
            )
            return ai_utils.RenameResult(fail=1)

        if not result["success"]:
            ai_utils.log(
                f"[!] AI 分析失败 (耗时 {ai_utils.format_elapsed(elapsed)}): "
                f"{result['message']}\n"
            )
            return ai_utils.RenameResult(fail=1)

        ai_utils.log(
            f"[+] AI 重命名分析完成 (耗时 {ai_utils.format_elapsed(elapsed)})\n"
        )

        parsed = ai_utils.parse_ai_response(result["message"])
        if parsed is None:
            ai_utils.log("[!] 无法解析 AI 响应为 JSON\n")
            raw_preview = result["message"][:300]
            ai_utils.log(f"[*] AI 原始响应: {raw_preview}\n")
            return ai_utils.RenameResult(fail=1)

        s, f = self._apply_all(parsed, dry_run)
        return ai_utils.RenameResult(
            success=s, fail=f, details=self.last_details,
        )


def rename_functions(pattern, dry_run=False, recursive=False,
                     max_depth=ai_utils.DEFAULT_MAX_DEPTH):
    """批量 AI 辅助符号重命名。

    Args:
        pattern: 函数名或通配符模式。
        dry_run: 仅预览，不实际重命名。
        recursive: 递归分析被调用的自动命名函数。
        max_depth: 递归最大深度。

    Returns:
        (total_success, total_fail, total_functions) 元组。
    """
    ai_utils.log(
        f"[*] 开始 AI 辅助符号重命名: pattern='{pattern}', "
        f"dry_run={dry_run}, recursive={recursive}, "
        f"max_depth={max_depth}\n"
    )

    def _processor(func, depth, idx):
        context, cfunc, source = ai_utils.collect_function_context(func)
        symbols = ai_utils.extract_all_symbols(func, cfunc, source)
        symbol_count = ai_utils.count_symbols(symbols)

        if symbol_count == 0:
            ai_utils.log("  [*] 无可重命名的符号，跳过重命名\n")
            return 0, 0

        renamer = AIRenamer(func, context, cfunc, source, symbols)
        result = renamer.analyze(dry_run)
        return result.success, result.fail

    return ai_utils.process_functions(
        pattern, _processor, recursive, max_depth, "重命名"
    )
