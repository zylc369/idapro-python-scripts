# -*- coding: utf-8 -*-
"""summary: AI 辅助分析统合入口

description:
  统合 ai_rename（符号重命名）和 ai_comment（注释生成）两个功能模块，
  提供统一的命令行接口。

  支持三个子命令：
    - rename:  AI 辅助符号重命名（函数、局部变量、全局数据、结构体字段）
    - comment: AI 辅助注释生成（函数摘要 + 行内注释，汇编 + 伪代码双写）
    - analyze: 完整分析（先重命名再生成注释，注释基于重命名后的代码）

  三种运行模式：
    1. 对话框模式（IDA GUI 内，无参数）：
         exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())

    2. CLI 模式（IDA GUI 内，通过 sys.argv 传参）：
         import sys
         sys.argv = ["", "rename", "--pattern", "main_0", "--recursive"]
         exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())

    3. Headless 模式（命令行，通过 idat -A -S 调用，环境变量传参）：
         IDA_COMMAND=rename IDA_PATTERN="main_0" \
           idat -A -S"disassembler/ai_analyze.py" binary.i64

  扩展新命令时，只需：
    1. 在 disassembler/ 下创建新的 ai_xxx.py 模块
    2. 在本文件中 import 并注册到 _COMMAND_HANDLERS
    3. 在 _parse_cli_argv / _AnalyzeForm / _parse_env_args 中添加对应参数

level: advanced
"""

import argparse
import os
import sys

import ida_kernwin

_script_dir = ""
try:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
except (NameError, TypeError):
    pass

if not _script_dir or not os.path.isdir(_script_dir):
    _script_dir = os.path.join(os.getcwd(), "disassembler")

_project_root = os.path.dirname(_script_dir)

for _p in [_script_dir, _project_root]:
    if _p and _p not in sys.path:
        sys.path.insert(0, _p)

import ai_utils
import ai_rename
import ai_comment


# ─────────────────────────────────────────────────────────────
#  完整分析：先重命名，再注释
# ─────────────────────────────────────────────────────────────

def analyze_functions(pattern, dry_run=False, recursive=False,
                      max_depth=ai_utils.DEFAULT_MAX_DEPTH):
    """完整分析：先重命名符号，再基于重命名后的代码生成注释。"""
    ai_utils.log(
        f"[*] 开始 AI 完整分析（重命名 + 注释）: pattern='{pattern}', "
        f"dry_run={dry_run}, recursive={recursive}, "
        f"max_depth={max_depth}\n"
    )

    def _processor(func, depth, idx):
        context, cfunc, source = ai_utils.collect_function_context(func)
        symbols = ai_utils.extract_all_symbols(func, cfunc, source)
        symbol_count = ai_utils.count_symbols(symbols)

        total_success = 0
        total_fail = 0

        if symbol_count > 0:
            renamer = ai_rename.AIRenamer(func, context, cfunc, source, symbols)
            s, f = renamer.analyze(dry_run)
            total_success += s
            total_fail += f
        else:
            ai_utils.log("  [*] 无可重命名的符号，跳过重命名\n")

        if not dry_run:
            new_cfunc = ai_utils.decompile_function(func)
            if new_cfunc:
                cfunc = new_cfunc
                source = str(cfunc)
                context["source"] = source
                ai_utils.log(
                    "[*] 重新反编译获取重命名后的代码，用于注释生成\n"
                )

        commenter = ai_comment.AICommenter(func, context, cfunc, source)
        s, f = commenter.analyze(dry_run)
        total_success += s
        total_fail += f

        return total_success, total_fail

    return ai_utils.process_functions(
        pattern, _processor, recursive, max_depth, "完整分析"
    )


# ─────────────────────────────────────────────────────────────
#  命令分发
# ─────────────────────────────────────────────────────────────

_COMMAND_HANDLERS = {
    "rename": ai_rename.rename_functions,
    "comment": ai_comment.comment_functions,
    "analyze": analyze_functions,
}

_VALID_COMMANDS = list(_COMMAND_HANDLERS.keys())


def _dispatch(command, pattern, dry_run=False, recursive=False,
              max_depth=ai_utils.DEFAULT_MAX_DEPTH):
    """根据命令名分发到对应的处理函数。"""
    handler = _COMMAND_HANDLERS.get(command)
    if handler is None:
        ai_utils.log(
            f"[!] 未知命令: {command}，有效命令: {', '.join(_VALID_COMMANDS)}\n"
        )
        return False

    result = handler(pattern, dry_run=dry_run, recursive=recursive,
                     max_depth=max_depth)
    total_success, total_fail, total = result
    return total_success > 0


# ─────────────────────────────────────────────────────────────
#  对话框模式
# ─────────────────────────────────────────────────────────────

class _AnalyzeForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* 开始分析
BUTTON CANCEL 取消
AI 辅助分析

<#分析命令#>{command}>
<##函数名或通配符模式 (如 sub_123* 或 main) :{pattern}>
<{recursive}>递归分析被调用的自动命名函数>
<##递归最大深度 (默认 2):{max_depth}>
<{dry_run}>仅预览（不实际执行）>
""",
            {
                "command": F.DropdownListControlType(
                    items=["重命名符号 (rename)", "生成注释 (comment)", "完整分析 (analyze)"],
                    selval=0,
                ),
                "pattern": F.StringInput(),
                "recursive": F.BoolInput(),
                "max_depth": F.StringInput(),
                "dry_run": F.BoolInput(),
            },
        )


def show_dialog():
    f = _AnalyzeForm()
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        command_idx = f.command.value
        command = _VALID_COMMANDS[command_idx] if command_idx < len(_VALID_COMMANDS) else "analyze"
        pattern = (f.pattern.value or "").strip()
        recursive = bool(f.recursive.value)
        max_depth_str = (f.max_depth.value or "").strip()
        dry_run = bool(f.dry_run.value)
        try:
            max_depth = int(max_depth_str) if max_depth_str else ai_utils.DEFAULT_MAX_DEPTH
        except ValueError:
            max_depth = ai_utils.DEFAULT_MAX_DEPTH
        if pattern:
            ai_utils.log(f"[*] 对话框模式: 用户确认分析，命令={command}\n")
            _dispatch(command, pattern, dry_run=dry_run,
                      recursive=recursive, max_depth=max_depth)
        else:
            ai_utils.log("[!] 已取消: 函数名或模式不能为空\n")
    else:
        ai_utils.log("[*] 对话框模式: 用户取消操作\n")
    f.Free()


# ─────────────────────────────────────────────────────────────
#  CLI 模式
# ─────────────────────────────────────────────────────────────

def _parse_cli_argv(argv):
    """解析 CLI 参数，返回 (command, pattern, dry_run, recursive, max_depth) 或 None。"""
    args = argv[1:]
    if not args:
        return None

    try:
        parser = argparse.ArgumentParser(
            prog="ai_analyze",
            description="AI 辅助分析（IDA Pro 内 CLI 模式）",
        )
        subparsers = parser.add_subparsers(dest="command", required=True)

        for cmd_name in _VALID_COMMANDS:
            sub = subparsers.add_parser(cmd_name)
            sub.add_argument("--pattern", "-p", required=True,
                             help="函数名或通配符模式")
            sub.add_argument("--dry-run", action="store_true",
                             help="仅预览，不实际执行")
            sub.add_argument("--recursive", "-r", action="store_true",
                             help="递归分析被调用的自动命名函数")
            sub.add_argument("--max-depth", type=int,
                             default=ai_utils.DEFAULT_MAX_DEPTH,
                             help=f"递归最大深度（默认 {ai_utils.DEFAULT_MAX_DEPTH}）")

        parsed = parser.parse_args(args)
        return (
            parsed.command,
            parsed.pattern,
            parsed.dry_run,
            parsed.recursive,
            parsed.max_depth,
        )
    except (SystemExit, Exception):
        return None


# ─────────────────────────────────────────────────────────────
#  Headless 模式
# ─────────────────────────────────────────────────────────────

def _parse_env_args():
    """从环境变量读取 headless 参数。"""
    command = os.environ.get("IDA_COMMAND", "").strip().lower()
    pattern = os.environ.get("IDA_PATTERN", "").strip()
    dry_run = bool(os.environ.get("IDA_DRY_RUN", "").strip())
    recursive = bool(os.environ.get("IDA_RECURSIVE", "").strip())
    try:
        max_depth = int(os.environ.get("IDA_MAX_DEPTH", "").strip())
    except (ValueError, AttributeError):
        max_depth = ai_utils.DEFAULT_MAX_DEPTH

    ai_utils.log(
        f"[*] 环境变量: IDA_COMMAND='{command}', "
        f"IDA_PATTERN='{pattern}', "
        f"IDA_DRY_RUN='{dry_run}', IDA_RECURSIVE='{recursive}', "
        f"IDA_MAX_DEPTH='{max_depth}'\n"
    )

    if not command or command not in _VALID_COMMANDS:
        ai_utils.log(
            f"[!] IDA_COMMAND 无效: '{command}'，"
            f"有效值: {', '.join(_VALID_COMMANDS)}\n"
        )
        return None
    if not pattern:
        ai_utils.log("[!] IDA_PATTERN 不能为空\n")
        return None
    return command, pattern, dry_run, recursive, max_depth


def _run_headless(command, pattern, dry_run=False, recursive=False,
                  max_depth=ai_utils.DEFAULT_MAX_DEPTH):
    """idat headless 入口：等待分析 → 执行 → 保存 → 退出。"""
    import ida_auto
    import ida_loader
    import ida_pro

    ai_utils.log("[*] headless 模式: 等待 IDA 自动分析完成...\n")
    ida_auto.auto_wait()
    ai_utils.log("[*] headless 模式: 自动分析完成，开始 AI 分析\n")

    success = _dispatch(command, pattern, dry_run=dry_run,
                        recursive=recursive, max_depth=max_depth)

    if success and not dry_run:
        ai_utils.log("[*] headless 模式: 正在保存数据库...\n")
        ida_loader.save_database(None, 0)
        ai_utils.log("[+] headless 模式: 数据库已保存\n")

    exit_code = 0 if success else 1
    ai_utils.log(
        f"[{'+'if success else '!'}] headless 模式: "
        f"分析{'成功' if success else '失败'}，"
        f"正在退出 (exit code {exit_code})\n"
    )
    ida_pro.qexit(exit_code)


# ─────────────────────────────────────────────────────────────
#  模块级入口
# ─────────────────────────────────────────────────────────────

_batch = bool(ida_kernwin.cvar.batch)
_env = _parse_env_args()

if _batch and _env is not None:
    ai_utils.log("[*] 检测到 headless 模式 (batch=True)，使用环境变量参数\n")
    _run_headless(
        _env[0], _env[1], dry_run=_env[2],
        recursive=_env[3], max_depth=_env[4],
    )
elif _batch:
    ai_utils.log("[!] headless 模式需要设置 IDA_COMMAND 和 IDA_PATTERN 环境变量\n")
    import ida_pro
    ida_pro.qexit(1)
elif __name__ == "__main__":
    has_args = len(sys.argv) > 1
    cli_result = _parse_cli_argv(sys.argv)
    sys.argv = sys.argv[:1]
    if cli_result is not None:
        ai_utils.log("[*] CLI 模式: 使用命令行参数\n")
        _dispatch(
            cli_result[0], cli_result[1], dry_run=cli_result[2],
            recursive=cli_result[3], max_depth=cli_result[4],
        )
    else:
        if has_args:
            ai_utils.log(
                "[!] 参数格式错误，正确格式: "
                "<rename|comment|analyze> --pattern <函数名或模式> "
                "[--dry-run] [--recursive] [--max-depth <N>]\n"
            )
        ai_utils.log("[*] 对话框模式: 等待用户输入\n")
        show_dialog()
