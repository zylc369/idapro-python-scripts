# -*- coding: utf-8 -*-
"""summary: AI 辅助注释生成

description:
  使用 AI 分析函数的反编译代码，自动生成中文注释，包括：
    - 函数摘要注释（汇编视图 + 伪代码视图双写）
    - 行内注释（关键逻辑步骤的中文注释，汇编视图 + 伪代码视图双写）

  本模块为内部模块，通过 ai_analyze.py 的 comment 子命令调用。
  也可在 AIRenamer 之后配合使用以获得更好的注释质量
  （通过 ai_analyze.py 的 analyze 子命令）。

  编程方式调用（IDA GUI 内，需先确保 disassembler/ 在 sys.path 中）：

    import ai_comment
    ai_comment.comment_functions("main_0", dry_run=False, recursive=True)

level: advanced
"""

import os
import sys
import time

import ida_bytes
import ida_funcs
import ida_idaapi

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


class AICommenter:
    """AI 辅助注释生成（函数摘要 + 行内注释，汇编视图 + 伪代码视图双写）。

    可独立使用，也可在 AIRenamer 之后调用以获得更好的注释质量
    （基于重命名后的代码生成注释）。
    """

    def __init__(self, func, context, cfunc, source):
        self.func = func
        self.func_name = ida_funcs.get_func_name(func.start_ea)
        self.context = context
        self.cfunc = cfunc
        self.source = source
        self.last_summary = ""
        self.last_inline_comments = {}

    def _build_prompt(self):
        sections = []

        sections.append(
            "你是一位资深的逆向工程专家。"
            "请分析以下反编译代码，为函数生成中文注释。\n"
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

        sections.append("## 反编译伪代码（带行号标注）")
        source_lines = self.source.splitlines()
        total_lines = len(source_lines)
        display_lines = source_lines[:ai_utils.MAX_SOURCE_LINES]
        numbered_lines = []
        for i, line in enumerate(display_lines, 1):
            numbered_lines.append(f"{i:>4}: {line}")
        if total_lines > ai_utils.MAX_SOURCE_LINES:
            numbered_lines.append(
                f"  ... (已截断，共 {total_lines} 行)"
            )
        sections.append("```c")
        sections.extend(numbered_lines)
        sections.append("```\n")

        sections.append("## 输出格式")
        sections.append(
            "请严格按照以下 JSON 格式返回，不要添加任何其他内容：\n"
        )
        sections.append("```json")
        sections.append("{")
        sections.append('  "summary_comment": "函数功能的一句话中文摘要",')
        sections.append('  "inline_comments": {')
        sections.append('    "3": "读取用户名输入",')
        sections.append('    "5": "调用验证函数校验凭据"')
        sections.append("  }")
        sections.append("}")
        sections.append("```")
        sections.append("")
        sections.append(
            "inline_comments 是对反编译伪代码关键行的中文注释，"
            "键为行号（从 1 开始，不包含 ``` 标记行），值为中文注释。"
            "只注释关键的逻辑步骤（如函数调用、条件判断、重要赋值），"
            "不要注释每一行，3-8 条注释为宜。"
        )
        sections.append(
            "summary_comment 是函数功能的一句话中文摘要，"
            "用简洁自然的语言描述，不要过于冗长。"
        )

        return "\n".join(sections)

    def _apply_comments(self, ai_result, dry_run=False):
        if not self.cfunc:
            return 0, 0

        if not ai_utils._HAS_DECOMPILER:
            ai_utils.log("[!] 注释生成需要 Hex-Rays 反编译器\n")
            return 0, 0

        summary = ai_result.get("summary_comment", "")
        inline_comments = ai_result.get("inline_comments", {})

        self.last_summary = summary
        self.last_inline_comments = dict(inline_comments)

        if not summary and not inline_comments:
            return 0, 0

        total_success = 0
        total_fail = 0

        if dry_run:
            if summary:
                ai_utils.log(f"  [预览-函数摘要] {summary}\n")
            for line_no, cmt in sorted(
                inline_comments.items(), key=lambda x: int(x[0])
            ):
                ai_utils.log(f"  [预览-行内注释] 第{line_no}行: {cmt}\n")
            return len(inline_comments) + (1 if summary else 0), 0

        if summary:
            ida_bytes.set_cmt(self.func.start_ea, summary, 0)
            ai_utils.log(f"  [+] 汇编注释(函数入口): {summary}\n")
            tl = ida_hexrays.treeloc_t()
            tl.ea = self.func.start_ea
            tl.itp = ida_hexrays.ITP_BLOCK1
            self.cfunc.set_user_cmt(tl, summary)
            total_success += 1

        if inline_comments:
            source_lines = self.source.splitlines()
            ea_by_line = {}
            for item in self.cfunc.treeitems:
                if item.ea != ida_idaapi.BADADDR:
                    for i, line in enumerate(source_lines):
                        if item.ea not in ea_by_line.values():
                            if (
                                f"0x{item.ea:X}" in line
                                or f"0x{item.ea:08X}" in line
                            ):
                                ea_by_line[i + 1] = item.ea
                                break

            if not ea_by_line:
                body_ea = {}
                for item in self.cfunc.treeitems:
                    if item.ea != ida_idaapi.BADADDR:
                        body_ea[item.ea] = item
                sorted_eas = sorted(body_ea.keys())
                line_count = len(source_lines)

                for line_no_str in inline_comments:
                    try:
                        line_no = int(line_no_str)
                    except (ValueError, TypeError):
                        continue
                    idx = max(
                        0,
                        min(
                            int(
                                (line_no - 1)
                                * len(sorted_eas)
                                / max(line_count, 1)
                            ),
                            len(sorted_eas) - 1,
                        ),
                    )
                    ea_by_line[line_no] = sorted_eas[idx]

            for line_no_str, comment_text in inline_comments.items():
                try:
                    line_no = int(line_no_str)
                except (ValueError, TypeError):
                    ai_utils.log(f"  [!] 无效行号: {line_no_str}\n")
                    total_fail += 1
                    continue

                ea = ea_by_line.get(line_no)
                if ea is None:
                    ai_utils.log(
                        f"  [!] 无法映射行号 {line_no} 到地址\n"
                    )
                    total_fail += 1
                    continue

                tl = ida_hexrays.treeloc_t()
                tl.ea = ea
                tl.itp = ida_hexrays.ITP_SEMI
                self.cfunc.set_user_cmt(tl, comment_text)

                ida_bytes.set_cmt(ea, comment_text, 0)
                ai_utils.log(
                    f"  [+] 行内注释(0x{ea:08X} 第{line_no}行): "
                    f"{comment_text}\n"
                )
                total_success += 1

        self.cfunc.save_user_cmts()
        return total_success, total_fail

    def analyze(self, dry_run=False):
        """执行 AI 辅助注释生成。

        返回 CommentResult。
        """
        ai_utils.log("[*] 正在调用 AI 生成注释...\n")
        prompt = self._build_prompt()

        start_time = time.time()
        result = ai_utils.call_ai(prompt)
        elapsed = time.time() - start_time

        if result is None:
            ai_utils.log(
                f"[!] AI 调用失败 (耗时 {ai_utils.format_elapsed(elapsed)})\n"
            )
            return ai_utils.CommentResult(fail=1)

        if not result["success"]:
            ai_utils.log(
                f"[!] AI 分析失败 (耗时 {ai_utils.format_elapsed(elapsed)}): "
                f"{result['message']}\n"
            )
            return ai_utils.CommentResult(fail=1)

        ai_utils.log(
            f"[+] AI 注释生成完成 (耗时 {ai_utils.format_elapsed(elapsed)})\n"
        )

        parsed = ai_utils.parse_ai_response(result["message"])
        if parsed is None:
            ai_utils.log("[!] 无法解析 AI 响应为 JSON\n")
            raw_preview = result["message"][:300]
            ai_utils.log(f"[*] AI 原始响应: {raw_preview}\n")
            return ai_utils.CommentResult(fail=1)

        s, f = self._apply_comments(parsed, dry_run)
        return ai_utils.CommentResult(
            success=s, fail=f,
            summary=self.last_summary,
            inline_comments=self.last_inline_comments,
        )


def comment_functions(pattern, dry_run=False, recursive=False,
                      max_depth=ai_utils.DEFAULT_MAX_DEPTH):
    """批量 AI 辅助注释生成。

    Args:
        pattern: 函数名或通配符模式。
        dry_run: 仅预览，不实际写入注释。
        recursive: 递归分析被调用的自动命名函数。
        max_depth: 递归最大深度。

    Returns:
        (total_success, total_fail, total_functions) 元组。
    """
    ai_utils.log(
        f"[*] 开始 AI 辅助注释生成: pattern='{pattern}', "
        f"dry_run={dry_run}, recursive={recursive}, "
        f"max_depth={max_depth}\n"
    )

    def _processor(func, depth, idx):
        context, cfunc, source = ai_utils.collect_function_context(func)
        commenter = AICommenter(func, context, cfunc, source)
        return commenter.analyze(dry_run)

    return ai_utils.process_functions(
        pattern, _processor, recursive, max_depth, "注释"
    )
