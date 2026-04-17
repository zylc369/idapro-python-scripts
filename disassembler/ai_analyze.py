# -*- coding: utf-8 -*-
"""summary: AI 辅助分析统合入口

description:
  统合所有 AI 分析功能（重命名、注释等），支持多选组合。
  脚本自动检测运行环境，无需 shell wrapper：

  - IDA 内（exec / idat -S）：直接执行分析逻辑
  - 终端内（python）：自动调用 idat 执行 headless 分析

  功能以标志形式指定，可任意组合：
    --rename --comment        同时执行重命名和注释
    --rename                  仅重命名
    --comment                 仅注释

  通用参数（所有功能共享）：
    --pattern, --dry-run, --recursive, --max-depth

  扩展新功能时，只需：
    1. 在 disassembler/ 下创建新的 ai_xxx.py 模块
    2. 在本文件 _ACTIONS 列表中添加一条注册
    3. 在 _IN_IDA 块中添加对应的 _handle_xxx 处理函数

  三种运行模式：

    1. 对话框模式（IDA GUI 内，无参数）：
         exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())

    2. CLI 模式（IDA GUI 内，通过 sys.argv 传参）：
         import sys
         sys.argv = ["", "--rename", "--comment", "--pattern", "main_0"]
         exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())

    3. 终端 headless 模式（直接用 python 调用，自动调用 idat）：
         python disassembler/ai_analyze.py --rename --comment \
           --pattern "main_0" --input binary.i64

level: advanced
"""

import argparse
import json
import os
import re
import subprocess
import sys


# ─────────────────────────────────────────────────────────────
#  IDA 环境检测
# ─────────────────────────────────────────────────────────────

_IN_IDA = False
try:
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────
#  路径设置
# ─────────────────────────────────────────────────────────────

_script_dir = ""
try:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
except (NameError, TypeError):
    pass

if not _script_dir or not os.path.isdir(_script_dir):
    _script_dir = os.path.join(os.getcwd(), "disassembler")

_project_root = os.path.dirname(_script_dir)


# ─────────────────────────────────────────────────────────────
#  动作定义（IDA 和终端环境共享）
# ─────────────────────────────────────────────────────────────

# 注册新功能：在此列表追加一条即可
_ACTIONS = [
    {
        "name": "rename",
        "flag": "--rename",
        "help": "AI 辅助符号重命名（函数、局部变量、全局数据、结构体字段）",
    },
    {
        "name": "comment",
        "flag": "--comment",
        "help": "AI 辅助注释生成（函数摘要 + 行内注释）",
    },
]

# 扩展点：动作特定参数
# 格式: {"动作名": [{"flags": [...], "kwargs": {...}}, ...]}
# 示例:
#   _ACTION_SPECIFIC_ARGS = {
#       "rename": [{"flags": ["--rename-max-symbols"], "kwargs": {"type": int, "default": 50}}],
#   }
_ACTION_SPECIFIC_ARGS = {}

_DEFAULT_LOG_FILENAME = "ai_analyze.log"


def _build_parser():
    """构建 argparse 解析器（IDA 和终端环境共用）。"""
    parser = argparse.ArgumentParser(
        prog="ai_analyze",
        description="AI 辅助分析（可任意组合多个功能）",
    )

    for act in _ACTIONS:
        parser.add_argument(
            act["flag"], action="store_true", dest=f"action_{act['name']}",
            help=act["help"],
        )

    parser.add_argument("--pattern", "-p", help="函数名或通配符模式")
    parser.add_argument("--dry-run", action="store_true", help="仅预览，不实际执行")
    parser.add_argument(
        "--recursive", "-r", action="store_true",
        help="递归分析被调用的自动命名函数",
    )
    parser.add_argument(
        "--max-depth", type=int, default=2,
        help="递归最大深度（默认 2）",
    )

    # 终端 headless 专用参数（IDA 内自动忽略）
    parser.add_argument("--input", "-i", help="目标文件（终端模式必填）")
    parser.add_argument("--ida-path", help="IDA Pro 安装目录路径")
    parser.add_argument("--log", "-l", help=f"日志文件路径（默认: {_DEFAULT_LOG_FILENAME}）")

    # 动作特定参数
    for act_name, arg_defs in _ACTION_SPECIFIC_ARGS.items():
        for arg_def in arg_defs:
            parser.add_argument(*arg_def["flags"], **arg_def["kwargs"])

    return parser


def _get_selected_actions(args):
    """从解析结果中提取用户选中的动作名列表（按注册顺序）。"""
    selected = []
    for act in _ACTIONS:
        if getattr(args, f"action_{act['name']}", False):
            selected.append(act["name"])
    return selected


# ═══════════════════════════════════════════════════════════════
#  IDA 环境（IDAPython 脚本）
# ═══════════════════════════════════════════════════════════════

if _IN_IDA:

    for _p in [_script_dir, _project_root]:
        if _p and _p not in sys.path:
            sys.path.insert(0, _p)

    import ai_utils
    import ai_rename
    import ai_comment
    from collections import OrderedDict

    # ─── 动作上下文 ────────────────────────────────────────────

    class _ActionContext:
        """函数级别的可变上下文，在多个动作处理器间传递。"""

        def __init__(self, func):
            self.func = func
            self.context, self.cfunc, self.source = ai_utils.collect_function_context(func)
            self._needs_refresh = False

        def mark_for_refresh(self):
            self._needs_refresh = True

        def refresh_if_needed(self, dry_run):
            if not self._needs_refresh or dry_run:
                return
            new_cfunc = ai_utils.decompile_function(self.func)
            if new_cfunc:
                self.cfunc = new_cfunc
                self.source = str(self.cfunc)
                self.context["source"] = self.source
                ai_utils.log("[*] 重新反编译以获取更新后的代码\n")
            self._needs_refresh = False

    # ─── 动作处理器 ────────────────────────────────────────────

    _ACTION_HANDLERS = OrderedDict()

    def _register_handler(name, handler):
        _ACTION_HANDLERS[name] = handler

    def _handle_rename(actx, dry_run):
        func_name = ida_funcs.get_func_name(actx.func.start_ea)
        symbols = ai_utils.extract_all_symbols(actx.func, actx.cfunc, actx.source)
        symbol_count = ai_utils.count_symbols(symbols)
        ai_utils.log(
            f"  [rename] {func_name}: "
            f"可重命名符号 {symbol_count} 个"
            f"（局部变量 {len(symbols['local_vars'])}, "
            f"函数 {len(symbols['called_functions'])}, "
            f"全局数据 {len(symbols['global_data'])}, "
            f"结构体字段 {sum(len(v) for v in symbols['struct_fields'].values())}）\n"
        )
        if symbol_count == 0:
            return ai_utils.RenameResult(
                symbols_total=0,
                symbols_by_type={
                    "local_vars": len(symbols["local_vars"]),
                    "called_functions": len(symbols["called_functions"]),
                    "global_data": len(symbols["global_data"]),
                    "struct_fields": sum(len(v) for v in symbols["struct_fields"].values()),
                },
            )
        renamer = ai_rename.AIRenamer(
            actx.func, actx.context, actx.cfunc, actx.source, symbols
        )
        result = renamer.analyze(dry_run)
        result.symbols_total = symbol_count
        result.symbols_by_type = {
            "local_vars": len(symbols["local_vars"]),
            "called_functions": len(symbols["called_functions"]),
            "global_data": len(symbols["global_data"]),
            "struct_fields": sum(len(v) for v in symbols["struct_fields"].values()),
        }
        if result.success > 0:
            actx.mark_for_refresh()
        return result

    def _handle_comment(actx, dry_run):
        func_name = ida_funcs.get_func_name(actx.func.start_ea)
        ai_utils.log(
            f"  [comment] {func_name}: 开始生成注释\n"
        )
        commenter = ai_comment.AICommenter(
            actx.func, actx.context, actx.cfunc, actx.source
        )
        return commenter.analyze(dry_run)

    _register_handler("rename", _handle_rename)
    _register_handler("comment", _handle_comment)

    # ─── 动作执行 ──────────────────────────────────────────────

    def _dispatch(actions, pattern, dry_run=False, recursive=False,
                  max_depth=ai_utils.DEFAULT_MAX_DEPTH):
        """按顺序组合执行多个动作，每个函数内部依次执行所有动作。

        返回 AnalysisResult。
        """
        if not actions:
            ai_utils.log("[!] 未指定任何动作\n")
            return ai_utils.AnalysisResult()

        labels = "+".join(actions)
        ai_utils.log(
            f"[*] 开始 AI 分析 ({labels}): pattern='{pattern}', "
            f"dry_run={dry_run}, recursive={recursive}, "
            f"max_depth={max_depth}\n"
        )

        func_results = []

        def _processor(func, depth, idx):
            actx = _ActionContext(func)
            func_name = ida_funcs.get_func_name(func.start_ea)
            far = ai_utils.FuncActionResults(
                name=func_name,
                addr=f"0x{func.start_ea:08X}",
                depth=depth,
            )

            for i, action_name in enumerate(actions):
                handler = _ACTION_HANDLERS.get(action_name)
                if handler is None:
                    ai_utils.log(f"[!] 未知动作: {action_name}\n")
                    continue
                ai_utils.log(f"[*] 执行动作: {action_name}\n")
                result = handler(actx, dry_run)
                far.actions[action_name] = result

                if i < len(actions) - 1:
                    actx.refresh_if_needed(dry_run)

            func_results.append(far)
            total_s = sum(a.success for a in far.actions.values() if hasattr(a, "success"))
            total_f = sum(a.fail for a in far.actions.values() if hasattr(a, "fail"))
            return total_s, total_f

        total_success, total_fail, total = ai_utils.process_functions(
            pattern, _processor, recursive, max_depth, labels
        )
        return ai_utils.AnalysisResult(
            functions=func_results,
            total_functions=total,
            total_success=total_success,
            total_fail=total_fail,
        )

    # ─── 结果格式化 ──────────────────────────────────────────

    _ACTION_LABELS = {
        "rename": "符号重命名",
        "comment": "注释生成",
    }

    def _format_results(analysis_result, actions, dry_run):
        """将 AnalysisResult 格式化为可读文本并写入结果文件。"""
        lines = []
        lines.append("")
        lines.append("===== 分析结果 =====")

        for action_name in actions:
            label = _ACTION_LABELS.get(action_name, action_name)
            lines.append("")
            lines.append(f"----- {label} -----")

            for far in analysis_result.functions:
                result = far.actions.get(action_name)
                if result is None:
                    continue

                depth_indent = "  " + "  " * far.depth
                depth_tag = f" (递归深度 {far.depth})" if far.depth > 0 else ""
                lines.append(f"{depth_indent}{far.name} ({far.addr}){depth_tag}")

                if action_name == "rename" and isinstance(result, ai_utils.RenameResult):
                    lines.append(
                        f"{depth_indent}  "
                        f"可重命名符号 {result.symbols_total} 个"
                    )
                    for d in result.details:
                        tag = "[预览]" if d.status == "preview" else f"[{d.status}]"
                        detail_line = (
                            f"{depth_indent}    {tag} "
                            f"{d.old} -> {d.new}"
                        )
                        if d.reason:
                            detail_line += f"  ({d.reason})"
                        lines.append(detail_line)

                elif action_name == "comment" and isinstance(result, ai_utils.CommentResult):
                    if result.summary:
                        tag = "[预览]" if dry_run else "[+]"
                        lines.append(
                            f"{depth_indent}  {tag} 函数摘要: {result.summary}"
                        )
                    for line_no in sorted(result.inline_comments.keys(), key=int):
                        cmt = result.inline_comments[line_no]
                        tag = "[预览]" if dry_run else "[+]"
                        lines.append(
                            f"{depth_indent}  {tag} 行内注释 第{line_no}行: {cmt}"
                        )

        lines.append("")
        lines.append(
            f"总计: {analysis_result.total_functions} 个函数 | "
            f"成功: {analysis_result.total_success} | "
            f"失败: {analysis_result.total_fail}"
        )

        text = "\n".join(lines) + "\n"
        results_file = os.environ.get("IDA_RESULTS_FILE", "")
        if results_file:
            try:
                with open(results_file, "w", encoding="utf-8") as f:
                    f.write(text)
            except OSError:
                pass

    # ─── 对话框模式 ────────────────────────────────────────────

    def show_dialog():
        F = ida_kernwin.Form

        action_lines = []
        controls = {}
        for act in _ACTIONS:
            ctrl_name = f"do_{act['name']}"
            action_lines.append(f"<{{{ctrl_name}}}>{act['help']}>")
            controls[ctrl_name] = F.BoolInput()

        controls["pattern"] = F.StringInput()
        controls["recursive"] = F.BoolInput()
        controls["max_depth"] = F.StringInput()
        controls["dry_run"] = F.BoolInput()

        form_body = "\n".join(action_lines) + (
            "\n<##函数名或通配符模式 (如 sub_123* 或 main) :{pattern}>\n"
            "<{recursive}>递归分析被调用的自动命名函数>\n"
            "<##递归最大深度 (默认 2):{max_depth}>\n"
            "<{dry_run}>仅预览（不实际执行）>\n"
        )
        form_str = (
            "STARTITEM 0\n"
            "BUTTON YES* 开始分析\n"
            "BUTTON CANCEL 取消\n"
            "AI 辅助分析\n\n"
            + form_body
        )

        class _Form(F):
            def __init__(self):
                F.__init__(self, form_str, controls)

        f = _Form()
        f.Compile()
        ok = f.Execute()
        if ok == 1:
            actions = []
            for act in _ACTIONS:
                ctrl_name = f"do_{act['name']}"
                if bool(getattr(f, ctrl_name).value):
                    actions.append(act["name"])
            pattern = (f.pattern.value or "").strip()
            recursive = bool(f.recursive.value)
            max_depth_str = (f.max_depth.value or "").strip()
            dry_run = bool(f.dry_run.value)
            try:
                max_depth = int(max_depth_str) if max_depth_str else ai_utils.DEFAULT_MAX_DEPTH
            except ValueError:
                max_depth = ai_utils.DEFAULT_MAX_DEPTH
            if not actions:
                ai_utils.log("[!] 已取消: 至少勾选一个功能\n")
            elif pattern:
                ai_utils.log(
                    f"[*] 对话框模式: 用户确认分析，动作={','.join(actions)}\n"
                )
                _dispatch(actions, pattern, dry_run=dry_run,
                          recursive=recursive, max_depth=max_depth)
            else:
                ai_utils.log("[!] 已取消: 函数名或模式不能为空\n")
        else:
            ai_utils.log("[*] 对话框模式: 用户取消操作\n")
        f.Free()

    # ─── Headless 模式 ─────────────────────────────────────────

    def _parse_env_args():
        actions_str = os.environ.get("IDA_ACTIONS", "").strip().lower()
        pattern = os.environ.get("IDA_PATTERN", "").strip()
        dry_run = bool(os.environ.get("IDA_DRY_RUN", "").strip())
        recursive = bool(os.environ.get("IDA_RECURSIVE", "").strip())
        try:
            max_depth = int(os.environ.get("IDA_MAX_DEPTH", "").strip())
        except ValueError:
            max_depth = ai_utils.DEFAULT_MAX_DEPTH

        valid_names = {act["name"] for act in _ACTIONS}
        actions = [a.strip() for a in actions_str.split(",") if a.strip()]
        invalid = [a for a in actions if a not in valid_names]

        ai_utils.log(
            f"[*] 环境变量: IDA_ACTIONS='{actions_str}', "
            f"IDA_PATTERN='{pattern}', "
            f"IDA_DRY_RUN='{dry_run}', IDA_RECURSIVE='{recursive}', "
            f"IDA_MAX_DEPTH='{max_depth}'\n"
        )

        if invalid:
            ai_utils.log(
                f"[!] IDA_ACTIONS 包含无效动作: {', '.join(invalid)}，"
                f"有效值: {', '.join(sorted(valid_names))}\n"
            )
            return None
        if not actions:
            ai_utils.log("[!] IDA_ACTIONS 不能为空\n")
            return None
        if not pattern:
            ai_utils.log("[!] IDA_PATTERN 不能为空\n")
            return None
        return actions, pattern, dry_run, recursive, max_depth

    def _run_headless(actions, pattern, dry_run=False, recursive=False,
                      max_depth=ai_utils.DEFAULT_MAX_DEPTH):
        import ida_auto
        import ida_loader
        import ida_pro

        ai_utils.log("[*] headless 模式: 等待 IDA 自动分析完成...\n")
        ida_auto.auto_wait()
        ai_utils.log("[*] headless 模式: 自动分析完成，开始 AI 分析\n")

        analysis_result = _dispatch(actions, pattern, dry_run=dry_run,
                                    recursive=recursive, max_depth=max_depth)

        _format_results(analysis_result, actions, dry_run)

        success = analysis_result.total_success > 0
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

    # ─── CLI 模式（IDA GUI 内） ────────────────────────────────

    def _parse_cli_argv(argv):
        args = argv[1:]
        if not args:
            return None
        try:
            parser = _build_parser()
            parsed = parser.parse_args(args)
            actions = _get_selected_actions(parsed)
            if not actions:
                ai_utils.log("[!] 至少指定一个动作标志（如 --rename, --comment）\n")
                return None
            if not parsed.pattern:
                ai_utils.log("[!] --pattern 不能为空\n")
                return None
            return actions, parsed.pattern, parsed.dry_run, parsed.recursive, parsed.max_depth
        except (SystemExit, Exception):
            return None

    # ─── 模块级入口 ────────────────────────────────────────────

    _batch = bool(ida_kernwin.cvar.batch)
    _env = _parse_env_args()

    if _batch and _env is not None:
        ai_utils.log("[*] 检测到 headless 模式 (batch=True)，使用环境变量参数\n")
        _run_headless(
            _env[0], _env[1], dry_run=_env[2],
            recursive=_env[3], max_depth=_env[4],
        )
    elif _batch:
        ai_utils.log("[!] headless 模式需要设置 IDA_ACTIONS 和 IDA_PATTERN 环境变量\n")
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
                    "--rename [--comment] --pattern <模式> "
                    "[--dry-run] [--recursive] [--max-depth <N>]\n"
                )
            ai_utils.log("[*] 对话框模式: 等待用户输入\n")
            show_dialog()


# ═══════════════════════════════════════════════════════════════
#  终端环境（CLI wrapper，自动调用 idat）
# ═══════════════════════════════════════════════════════════════

else:

    def _validate_ida_dir(ida_dir):
        ida_bin = os.path.join(ida_dir, "ida")
        idat_bin = os.path.join(ida_dir, "idat")
        return (
            os.path.isfile(ida_bin) and os.access(ida_bin, os.X_OK)
            and os.path.isfile(idat_bin) and os.access(idat_bin, os.X_OK)
        )

    def _detect_ida_path(explicit_path=None):
        config_file = os.path.join(_project_root, ".config", "ida_config.json")

        if explicit_path:
            if _validate_ida_dir(explicit_path):
                return explicit_path
            print(
                f"[!] 错误: 在目录 '{explicit_path}' 中未找到 ida 和 idat 命令",
                file=sys.stderr,
            )
            return None

        if os.path.isfile(config_file):
            try:
                with open(config_file, encoding="utf-8") as f:
                    config = json.load(f)
                config_path = config.get("ida_path", "")
                if config_path and _validate_ida_dir(config_path):
                    print(
                        f"[*] 从配置文件读取 IDA Pro 路径: {config_path}",
                        file=sys.stderr,
                    )
                    return config_path
            except Exception:
                pass

        try:
            user_path = input("请输入 IDA Pro 可执行文件目录路径: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return None

        if not user_path or not _validate_ida_dir(user_path):
            print(
                f"[!] 错误: 在目录 '{user_path}' 中未找到 ida 和 idat 命令",
                file=sys.stderr,
            )
            return None

        config_dir = os.path.dirname(config_file)
        os.makedirs(config_dir, exist_ok=True)
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump({"ida_path": user_path}, f, indent=2)
        print(f"[+] 已保存 IDA Pro 路径: {user_path}", file=sys.stderr)
        return user_path

    def _derive_id0_path(input_path):
        if input_path.endswith(".i64"):
            return input_path[:-4] + ".id0"
        if input_path.endswith(".idb"):
            return input_path[:-4] + ".id0"
        return input_path + ".id0"

    def _check_db_lock(input_path):
        id0_path = _derive_id0_path(input_path)
        if not os.path.isfile(id0_path):
            return True

        try:
            import fcntl
            with open(id0_path, "r") as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                except (IOError, OSError):
                    print(f"[!] 警告: IDA 数据库可能已被占用: {id0_path}", file=sys.stderr)
                    return False
        except Exception as e:
            print(f"[*] 数据库锁检测跳过: {e}", file=sys.stderr)
        return True

    def main():
        parser = _build_parser()
        args = parser.parse_args()

        actions = _get_selected_actions(args)
        if not actions:
            print("[!] 至少指定一个动作标志（如 --rename, --comment）", file=sys.stderr)
            sys.exit(1)
        if not args.pattern:
            print("[!] --pattern 不能为空", file=sys.stderr)
            sys.exit(1)
        if not args.input:
            print("[!] --input 不能为空（终端模式必填）", file=sys.stderr)
            sys.exit(1)

        input_file = os.path.abspath(args.input)
        if not os.path.isfile(input_file):
            print(f"[!] 目标文件不存在: {input_file}", file=sys.stderr)
            sys.exit(1)

        ida_dir = _detect_ida_path(args.ida_path)
        if not ida_dir:
            sys.exit(1)

        if not _check_db_lock(input_file):
            sys.exit(1)

        call_dir = os.getcwd()
        log_path = args.log or os.path.join(call_dir, _DEFAULT_LOG_FILENAME)
        if not os.path.isabs(log_path):
            log_path = os.path.join(call_dir, log_path)

        results_path = log_path + ".results"

        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "w", encoding="utf-8") as f:
                pass
        except OSError as e:
            print(f"[!] 无法创建日志文件: {log_path} ({e})", file=sys.stderr)
            sys.exit(1)

        actions_str = ",".join(actions)

        def _print(msg):
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{ts} {msg}", file=sys.stderr)

        _print(f"[*] 正在执行 AI 辅助分析...")
        _print(f"[*] 动作: {actions_str}")
        _print(f"[*] 匹配模式: {args.pattern}")
        _print(f"[*] 目标: {input_file}")
        _print(f"[*] 日志: {log_path}")

        idat_bin = os.path.join(ida_dir, "idat")
        script_path = os.path.abspath(__file__)
        env = {
            **os.environ,
            "IDA_ACTIONS": actions_str,
            "IDA_PATTERN": args.pattern,
            "IDA_DRY_RUN": "1" if args.dry_run else "",
            "IDA_RECURSIVE": "1" if args.recursive else "",
            "IDA_MAX_DEPTH": str(args.max_depth),
            "IDA_RESULTS_FILE": results_path,
        }

        import time

        try:
            proc = subprocess.Popen(
                [idat_bin, "-v", "-A", f"-L{log_path}", f"-S{script_path}", input_file],
                env=env,
            )
        except FileNotFoundError:
            _print(f"[!] idat 未找到: {idat_bin}")
            sys.exit(1)
        except OSError as e:
            _print(f"[!] 启动 idat 失败: {e}")
            sys.exit(1)

        progress_patterns = [
            r"\[\*\] =+ \[\d+\]",
            r"\[\+\] AI .+完成",
            r"\[!\]",
        ]
        progress_re = re.compile("|".join(progress_patterns))
        log_pos = 0
        prev_line = None

        while proc.poll() is None:
            time.sleep(0.5)
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(log_pos)
                    for line in f:
                        cleaned = re.sub(
                            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ ", "", line
                        ).strip()
                        if cleaned and progress_re.search(cleaned) and cleaned != prev_line:
                            print(f"  {cleaned}", file=sys.stderr)
                            prev_line = cleaned
                    log_pos = f.tell()
            except (OSError, IOError):
                pass

        exit_code = proc.returncode

        if os.path.isfile(results_path):
            with open(results_path, "r", encoding="utf-8") as f:
                print(f.read(), end="", file=sys.stderr)

        sys.exit(exit_code)

    if __name__ == "__main__":
        main()
