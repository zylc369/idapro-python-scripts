# -*- coding: utf-8 -*-
"""summary: 将函数反汇编导出到文件

description:
  根据函数名或十六进制地址，生成完整的反汇编列表（包括所有尾块），
  并写入指定的输出文件或目录。

  对话框模式（无参数 → 弹框）：
    exec(open("dump_func_disasm.py", encoding="utf-8").read())

  CLI 模式（通过 sys.argv 传参 → 不弹框）：
    import sys; sys.argv = ["", "main", "/tmp/output/"]; exec(open("dump_func_disasm.py", encoding="utf-8").read())
    import sys; sys.argv = ["", "0x401000", "/tmp/main.asm"]; exec(open("dump_func_disasm.py", encoding="utf-8").read())

  也可以加载后直接调用函数（同样不弹框）：
    exec(open("dump_func_disasm.py", encoding="utf-8").read())
    dump_func_disasm("main", "/tmp/output/")

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
    ea = ida_idaapi.BADADDR

    # 优先尝试解析为十六进制地址
    try:
        if func_id.startswith("0x") or func_id.startswith("0X"):
            ea = int(func_id, 16)
    except ValueError:
        pass

    # 尝试作为函数名查找
    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_id)

    if ea == ida_idaapi.BADADDR:
        return None

    return ida_funcs.get_func(ea)


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
    for chunk in ida_funcs.func_tail_iterator_t(func):
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
        return os.path.join(output_path, filename)

    return output_path


def dump_func_disasm(func_id, output_path):
    """将函数反汇编导出到文件。

    Args:
        func_id: 函数名（如 "main"）或十六进制地址（如 "0x401000"）。
        output_path: 输出文件路径，或目录（自动生成文件名）。

    Returns:
        成功返回 True，失败返回 False。
    """
    func = resolve_function(func_id)
    if func is None:
        ida_kernwin.msg(f"[!] 未找到函数: {func_id}\n")
        return False

    content = generate_disassembly(func)
    filepath = _resolve_output_path(output_path, func)

    parent = os.path.dirname(filepath)
    if parent and not os.path.exists(parent):
        try:
            os.makedirs(parent, exist_ok=True)
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
""",
            {
                "func_id": F.StringInput(),
                "output_path": F.StringInput(),
            },
        )


def show_dialog():
    f = _DumpForm()
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        func_id = (f.func_id.value or "").strip()
        output_path = (f.output_path.value or "").strip()
        if func_id and output_path:
            dump_func_disasm(func_id, output_path)
        else:
            ida_kernwin.msg("[!] 已取消: 函数标识和输出路径不能为空\n")
    f.Free()


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        func_id = sys.argv[1]
        output_path = sys.argv[2]
        sys.argv = sys.argv[:1]
        dump_func_disasm(func_id, output_path)
    else:
        show_dialog()
