# -*- coding: utf-8 -*-
"""summary: 将函数反汇编导出到文件

description:
  根据函数名或十六进制地址，生成完整的反汇编列表（包括所有尾块），
  并写入指定的输出文件或目录。

  对话框模式（IDA GUI 内，无参数 → 弹框）：
    exec(open("dump_func_disasm.py", encoding="utf-8").read())

  IDA GUI 内 CLI 模式（通过 sys.argv 传参 → 不弹框）：
    import sys
    sys.argv = ["", "--use-mode", "cli", "--addr", "main", "--output", "/tmp/output/", "--ai-decompiler"]
    exec(open("dump_func_disasm.py", encoding="utf-8").read())

  编程方式调用（IDA GUI 内）：
    exec(open("dump_func_disasm.py", encoding="utf-8").read())
    dump_func_disasm("main", "/tmp/output/", ai_decompiler=True)

  命令行 headless 模式（通过 idat -A -S 调用，用环境变量传参）：
    IDA_FUNC_ADDR=main IDA_OUTPUT=/tmp/output.asm IDA_AI_DECOMPILER=1 \
      idat -A -S"dump_func_disasm.py" binary.i64

  --ai-decompiler: 可选，生成汇编后调用 AI 反编译器，将汇编反编译为 Python/C/C++

  当 output_path 为目录时，脚本自动生成文件名，格式：<func_name>_0x<addr>.asm

level: intermediate
"""

import os
import sys

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_xref


def resolve_function(func_id):
    """将函数名或十六进制地址字符串解析为 func_t 对象。

    Args:
        func_id: 函数名（如 "main"）或十六进制地址（如 "0x401000"）

    Returns:
        成功返回 func_t，失败返回 None。
    """
    ida_kernwin.msg(f"[*] 正在解析函数标识: '{func_id}'\n")
    ea = ida_idaapi.BADADDR

    # 优先尝试解析为十六进制地址
    try:
        if func_id.startswith("0x") or func_id.startswith("0X"):
            ea = int(func_id, 16)
            ida_kernwin.msg(f"[*] 按十六进制地址解析 -> 0x{ea:X}\n")
    except ValueError:
        ida_kernwin.msg(f"[!] 十六进制地址解析失败，将尝试按函数名查找\n")

    # 尝试作为函数名查找
    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_id)
        if ea != ida_idaapi.BADADDR:
            ida_kernwin.msg(f"[*] 按函数名查找 '{func_id}' -> 0x{ea:X}\n")
        else:
            ida_kernwin.msg(f"[!] 未找到名为 '{func_id}' 的符号\n")

    if ea == ida_idaapi.BADADDR:
        return None

    func = ida_funcs.get_func(ea)
    if func is not None:
        ida_kernwin.msg(
            f"[+] 已定位函数: 0x{func.start_ea:08X} - "
            f"0x{func.end_ea:08X} ({func.size()} 字节)\n"
        )
    else:
        ida_kernwin.msg(f"[!] 地址 0x{ea:X} 不属于任何已知函数\n")
    return func


def _get_caller_summary(ea):
    """获取调用指定地址的函数摘要信息。"""
    callers = []
    xb = ida_xref.xrefblk_t()
    for ref in xb.crefs_to(ea):
        name = ida_funcs.get_func_name(ref)
        callers.append(f"{name} (0x{ref:X})" if name else f"0x{ref:X}")
    if callers:
        return "; 调用者: " + ", ".join(callers)
    return ""


def _iter_chunk_heads(start_ea, end_ea):
    """遍历指定地址范围内的所有指令头。"""
    ea = start_ea
    while ea < end_ea and ea != ida_idaapi.BADADDR:
        yield ea
        ea = ida_bytes.next_head(ea, end_ea)
        if ea == ida_idaapi.BADADDR:
            break


def generate_disassembly(func):
    """生成函数的完整反汇编文本（包含所有代码块）。

    Args:
        func: 有效的 func_t 对象。

    Returns:
        反汇编列表字符串。
    """
    lines = []

    func_name = ida_funcs.get_func_name(func.start_ea)
    func_size = func.size()

    lines.append(f"; 函数: {func_name}")
    lines.append(f"; 范围: 0x{func.start_ea:08X} - 0x{func.end_ea:08X}")
    lines.append(f"; 大小: {func_size} 字节")

    callers = _get_caller_summary(func.start_ea)
    if callers:
        lines.append(f"; {callers}")
    lines.append("")

    # 遍历所有代码块（主入口 + 尾块）
    chunk_count = 0
    instr_count = 0
    for chunk in ida_funcs.func_tail_iterator_t(func):
        chunk_count += 1
        is_main = chunk.start_ea == func.start_ea
        if not is_main:
            lines.append(
                f"; --- 尾块: 0x{chunk.start_ea:08X} - "
                f"0x{chunk.end_ea:08X} ---"
            )

        for ea in _iter_chunk_heads(chunk.start_ea, chunk.end_ea):
            disasm = ida_lines.generate_disasm_line(
                ea, ida_lines.GENDSM_REMOVE_TAGS
            )
            lines.append(f"0x{ea:08X}    {disasm}")
            instr_count += 1

    ida_kernwin.msg(
        f"[*] 反汇编生成完毕: {chunk_count} 个代码块, "
        f"{instr_count} 条指令\n"
    )
    return "\n".join(lines) + "\n"


def _resolve_output_path(output_path, func):
    """根据用户提供的路径确定最终输出文件路径。

    如果 output_path 指向已存在的目录（或以路径分隔符结尾），
    则根据函数名和地址自动生成文件名；否则直接使用 output_path。

    Returns:
        绝对文件路径字符串。
    """
    if output_path.endswith(os.sep) or os.path.isdir(output_path):
        func_name = ida_funcs.get_func_name(func.start_ea)
        safe_name = func_name.replace(":", "_").replace(" ", "_")
        filename = f"{safe_name}_0x{func.start_ea:X}.asm"
        resolved = os.path.join(output_path, filename)
        ida_kernwin.msg(f"[*] 输出路径为目录，自动生成文件名: {resolved}\n")
        return resolved

    ida_kernwin.msg(f"[*] 输出路径: {output_path}\n")
    return output_path


def _call_ai_decompiler(asm_path):
    """调用 AI 反编译器，对生成的汇编文件进行反编译。

    通过 ai.opencode.run_opencode 以非交互模式调用 opencode，
    将汇编文件反编译为 Python/C/C++ 代码，输出到汇编文件所在目录。

    Args:
        asm_path: 汇编文件的绝对路径。

    Returns:
        成功返回 True，失败返回 False。
    """
    asm_path = os.path.abspath(asm_path)
    asm_dir = os.path.dirname(asm_path)

    prompt = (
        f"反编译`{asm_path}`到`{asm_dir}`目录中，"
        "输出语言为C/C++或Python，优先使用Python。"
        "Python通常能够等价的表达C/C++逻辑，Python不需要考虑较为复杂的内存申请、释放，"
        "它的库也很丰富、易于安装。"
        "**Python代码必须严格保持与原汇编代码的功能等价性。**"
    )

    ida_kernwin.msg(f"[*] 正在调用 AI 反编译器...\n")
    ida_kernwin.msg(f"[*] 汇编文件: {asm_path}\n")
    ida_kernwin.msg(f"[*] 输出目录: {asm_dir}\n")

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
        return False

    result = run_opencode(prompt)

    if result["success"]:
        ida_kernwin.msg(f"[+] AI 反编译完成\n")
    else:
        ida_kernwin.msg(f"[!] AI 反编译失败: {result['message']}\n")

    return result["success"]


def dump_func_disasm(func_id, output_path, ai_decompiler=False):
    """将函数反汇编导出到文件。

    Args:
        func_id: 函数名（如 "main"）或十六进制地址（如 "0x401000"）。
        output_path: 输出文件路径，或目录（自动生成文件名）。
        ai_decompiler: 是否在导出后调用 AI 反编译器。默认 False。

    Returns:
        成功返回 True，失败返回 False。
    """
    ida_kernwin.msg(f"[*] 开始导出函数反汇编: func_id='{func_id}', output='{output_path}', ai_decompiler={ai_decompiler}\n")

    func = resolve_function(func_id)
    if func is None:
        ida_kernwin.msg(f"[!] 未找到函数: {func_id}\n")
        return False

    ida_kernwin.msg("[*] 正在生成反汇编内容...\n")
    content = generate_disassembly(func)
    filepath = _resolve_output_path(output_path, func)

    parent = os.path.dirname(filepath)
    if parent and not os.path.exists(parent):
        try:
            os.makedirs(parent, exist_ok=True)
            ida_kernwin.msg(f"[*] 已创建输出目录: {parent}\n")
        except OSError as e:
            ida_kernwin.msg(f"[!] 无法创建目录 {parent}: {e}\n")
            return False

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as e:
        ida_kernwin.msg(f"[!] 无法写入文件 {filepath}: {e}\n")
        return False

    func_name = ida_funcs.get_func_name(func.start_ea)
    ida_kernwin.msg(
        f"[+] 已导出 '{func_name}' (0x{func.start_ea:X}, "
        f"{func.size()} 字节) -> {filepath}\n"
    )

    if ai_decompiler:
        _call_ai_decompiler(filepath)

    return True


class _DumpForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* 导出
BUTTON CANCEL 取消
导出函数反汇编

<##函数名或地址 (如 main 或 0x401000) :{func_id}>
<##输出文件或目录路径:{output_path}>
<{ai_decompiler}>使用 AI 反编译>
""",
            {
                "func_id": F.StringInput(),
                "output_path": F.StringInput(),
                "ai_decompiler": F.BoolInput(),
            },
        )


def show_dialog():
    f = _DumpForm()
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        func_id = (f.func_id.value or "").strip()
        output_path = (f.output_path.value or "").strip()
        ai_decompiler = bool(f.ai_decompiler.value)
        if func_id and output_path:
            ida_kernwin.msg("[*] 对话框模式: 用户确认导出\n")
            dump_func_disasm(func_id, output_path, ai_decompiler=ai_decompiler)
        else:
            ida_kernwin.msg("[!] 已取消: 函数标识和输出路径不能为空\n")
    else:
        ida_kernwin.msg("[*] 对话框模式: 用户取消操作\n")
    f.Free()


def _parse_cli_argv(argv):
    """解析 CLI 参数，返回 (func_id, output_path, ai_decompiler) 或 None。

    合法格式：--use-mode cli --addr <值> --output <值> [--ai-decompiler]
    """
    args = argv[1:]
    if len(args) < 6:
        return None

    try:
        use_mode_idx = args.index("--use-mode")
    except ValueError:
        return None

    if use_mode_idx + 1 >= len(args) or args[use_mode_idx + 1] != "cli":
        return None

    try:
        addr_idx = args.index("--addr")
    except ValueError:
        return None

    if addr_idx + 1 >= len(args) or args[addr_idx + 1].startswith("--"):
        return None

    try:
        output_idx = args.index("--output")
    except ValueError:
        return None

    if output_idx + 1 >= len(args) or args[output_idx + 1].startswith("--"):
        return None

    ai_decompiler = "--ai-decompiler" in args

    return args[addr_idx + 1], args[output_idx + 1], ai_decompiler


def _parse_env_args():
    """从环境变量读取 headless 参数。

    Returns:
        (func_id, output_path, ai_decompiler) 元组，缺少必要参数时返回 None。
    """
    func_id = os.environ.get("IDA_FUNC_ADDR", "").strip()
    output_path = os.environ.get("IDA_OUTPUT", "").strip()
    ai_decompiler = bool(os.environ.get("IDA_AI_DECOMPILER", "").strip())
    ida_kernwin.msg(
        f"[*] 环境变量: IDA_FUNC_ADDR='{func_id}', IDA_OUTPUT='{output_path}', "
        f"IDA_AI_DECOMPILER='{ai_decompiler}'\n"
    )
    if func_id and output_path:
        return func_id, output_path, ai_decompiler
    return None


def _run_headless(func_id, output_path, ai_decompiler=False):
    """idat headless 入口：等待分析 → 导出 → 保存 → 退出。"""
    import ida_auto
    import ida_pro

    ida_kernwin.msg("[*] headless 模式: 等待 IDA 自动分析完成...\n")
    ida_auto.auto_wait()
    ida_kernwin.msg("[*] headless 模式: 自动分析完成，开始导出\n")

    success = dump_func_disasm(func_id, output_path, ai_decompiler=ai_decompiler)

    ida_kernwin.msg(
        f"[{'+'if success else '!'}] headless 模式: "
        f"导出{'成功' if success else '失败'}，正在退出 (exit code "
        f"{0 if success else 1})\n"
    )
    ida_pro.qexit(0 if success else 1)


# 注意：headless 入口逻辑必须在模块级执行，不能放在 if __name__ == "__main__" 内。
# 原因：IDA 通过 ida_idaapi.py 的 exec(code, g) 执行 -S 指定的脚本，
# 此时 __name__ 被设为脚本文件名而非 "__main__"，if __name__ == "__main__" 永远为 False。
# 因此用 ida_kernwin.cvar.batch 在模块级判断是否处于 headless 模式。

_batch = bool(ida_kernwin.cvar.batch)
_env = _parse_env_args()

if _batch and _env is not None:
    ida_kernwin.msg("[*] 检测到 headless 模式 (batch=True)，使用环境变量参数\n")
    _run_headless(_env[0], _env[1], ai_decompiler=_env[2])
elif _batch:
    ida_kernwin.msg(
        "[!] headless 模式需要设置 IDA_FUNC_ADDR 和 IDA_OUTPUT 环境变量\n"
    )
    import ida_pro
    ida_pro.qexit(1)
elif __name__ == "__main__":
    has_args = len(sys.argv) > 1
    cli_result = _parse_cli_argv(sys.argv)
    sys.argv = sys.argv[:1]
    if cli_result is not None:
        ida_kernwin.msg("[*] CLI 模式: 使用命令行参数\n")
        dump_func_disasm(cli_result[0], cli_result[1], ai_decompiler=cli_result[2])
    else:
        if has_args:
            ida_kernwin.msg(
                "[!] 参数格式错误，正确格式: "
                "--use-mode cli --addr <函数名或地址> --output <输出路径> [--ai-decompiler]\n"
            )
        ida_kernwin.msg("[*] 对话框模式: 等待用户输入\n")
        show_dialog()
