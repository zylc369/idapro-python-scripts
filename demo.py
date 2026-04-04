"""summary: IDA Pro demo script - list functions and their basic info

description:
  A demo script that lists all functions in the current IDB,
  showing address, name, size, and flags.
  Useful as a starting point for understanding IDAPython scripting.

level: beginner
"""

import ida_funcs
import ida_kernwin
import idautils

def list_functions():
    count = 0
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        func = ida_funcs.get_func(ea)
        if func is None:
            ida_kernwin.msg("Failed to get function at %x\n" % ea)
            continue

        size = func.size()
        flags = func.flags
        ida_kernwin.msg("0x%08X  %-40s  size=%-6d  flags=0x%x\n" % (ea, name, size, flags))
        count += 1

    ida_kernwin.msg("Total: %d function(s)\n" % count)


if __name__ == "__main__":
    list_functions()
