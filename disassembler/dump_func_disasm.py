"""summary: Dump function disassembly to file

description:
  Given a function name or hex address, generates a complete disassembly
  listing (including all tail chunks) and writes it to the specified
  output file or directory.

  Usage in IDA (interactive mode, will prompt for input):
    File -> Script file... -> dump_func_disasm.py

  Or call programmatically from IDAPython console:
    exec(open("dump_func_disasm.py").read())
    dump_func_disasm("main", "/tmp/output")         # by name, to directory
    dump_func_disasm("0x401000", "/tmp/main.asm")    # by address, to file

  When output_path is a directory, the script auto-generates a filename
  in the format: <func_name>_0x<addr>.asm

level: intermediate
"""

import os

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_xref


def resolve_function(func_id):
    """Resolve a function name or hex address string to a func_t object.

    Args:
        func_id: Function name (e.g. "main") or hex address (e.g. "0x401000")

    Returns:
        func_t on success, None on failure.
    """
    ea = ida_idaapi.BADADDR

    # Try as hex address first
    try:
        if func_id.startswith("0x") or func_id.startswith("0X"):
            ea = int(func_id, 16)
    except ValueError:
        pass

    # Try as function name
    if ea == ida_idaapi.BADADDR:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_id)

    if ea == ida_idaapi.BADADDR:
        return None

    return ida_funcs.get_func(ea)


def _get_caller_summary(ea):
    callers = []
    xb = ida_xref.xrefblk_t()
    for ref in xb.crefs_to(ea):
        name = ida_funcs.get_func_name(ref)
        callers.append(f"{name} (0x{ref:X})" if name else f"0x{ref:X}")
    if callers:
        return "; callers: " + ", ".join(callers)
    return ""


def _iter_chunk_heads(start_ea, end_ea):
    ea = start_ea
    while ea < end_ea and ea != ida_idaapi.BADADDR:
        yield ea
        ea = ida_bytes.next_head(ea, end_ea)
        if ea == ida_idaapi.BADADDR:
            break


def generate_disassembly(func):
    """Generate the full disassembly text for a function (all chunks).

    Args:
        func: A valid func_t object.

    Returns:
        The disassembly listing as a string.
    """
    lines = []

    func_name = ida_funcs.get_func_name(func.start_ea)
    func_size = func.size()

    lines.append(f"; Function: {func_name}")
    lines.append(f"; Range: 0x{func.start_ea:08X} - 0x{func.end_ea:08X}")
    lines.append(f"; Size: {func_size} byte(s)")

    callers = _get_caller_summary(func.start_ea)
    if callers:
        lines.append(f"; {callers}")
    lines.append("")

    # Iterate all chunks (main entry + tails)
    for chunk in ida_funcs.func_tail_iterator_t(func):
        is_main = chunk.start_ea == func.start_ea
        if not is_main:
            lines.append(
                f"; --- tail chunk: 0x{chunk.start_ea:08X} - "
                f"0x{chunk.end_ea:08X} ---"
            )

        for ea in _iter_chunk_heads(chunk.start_ea, chunk.end_ea):
            disasm = ida_lines.generate_disasm_line(
                ea, ida_lines.GENDSM_REMOVE_TAGS
            )
            lines.append(f"0x{ea:08X}    {disasm}")

    return "\n".join(lines) + "\n"


def _resolve_output_path(output_path, func):
    """Determine the final file path from a user-supplied output_path.

    If output_path points to an existing directory (or ends with a path
    separator), a filename based on the function name and address is
    generated automatically. Otherwise output_path is used as-is.

    Returns:
        Absolute file path as a string.
    """
    if output_path.endswith(os.sep) or os.path.isdir(output_path):
        func_name = ida_funcs.get_func_name(func.start_ea)
        safe_name = func_name.replace(":", "_").replace(" ", "_")
        filename = f"{safe_name}_0x{func.start_ea:X}.asm"
        return os.path.join(output_path, filename)

    return output_path


def dump_func_disasm(func_id, output_path):
    """Dump the disassembly of a function to a file.

    Args:
        func_id: Function name (e.g. "main") or hex address (e.g. "0x401000").
        output_path: Output file path, or directory (auto-generates filename).

    Returns:
        True on success, False on failure.
    """
    func = resolve_function(func_id)
    if func is None:
        ida_kernwin.msg(f"[!] Function not found: {func_id}\n")
        return False

    content = generate_disassembly(func)
    filepath = _resolve_output_path(output_path, func)

    parent = os.path.dirname(filepath)
    if parent and not os.path.exists(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            ida_kernwin.msg(f"[!] Cannot create directory {parent}: {e}\n")
            return False

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as e:
        ida_kernwin.msg(f"[!] Cannot write to {filepath}: {e}\n")
        return False

    func_name = ida_funcs.get_func_name(func.start_ea)
    ida_kernwin.msg(
        f"[+] Dumped '{func_name}' (0x{func.start_ea:X}, "
        f"{func.size()} bytes) -> {filepath}\n"
    )
    return True


if __name__ == "__main__":
    func_id = ida_kernwin.ask_str("", 0, "Function name or hex address:")
    if func_id is None or not func_id.strip():
        ida_kernwin.msg("[!] Cancelled: no function identifier provided\n")
    else:
        output_path = ida_kernwin.ask_str("", 0, "Output file or directory:")
        if output_path is None or not output_path.strip():
            ida_kernwin.msg("[!] Cancelled: no output path provided\n")
        else:
            dump_func_disasm(func_id.strip(), output_path.strip())
