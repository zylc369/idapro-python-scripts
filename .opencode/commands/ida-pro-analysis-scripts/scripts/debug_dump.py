# -*- coding: utf-8 -*-
"""summary: IDA 调试器脱壳 dump 脚本

description:
  在 IDA 调试器中运行目标程序到 OEP 断点，dump 内存段并重建 PE 文件。
  适用于任何壳（UPX/ASPack/自定义壳），只要壳不检测调试器。

  使用方式（idat headless）：
    IDA_OEP_ADDR=0x401000 IDA_OUTPUT=/tmp/unpacked.exe \
      idat -A -S"scripts/debug_dump.py" -L/tmp/debug.log target.i64

  环境变量：
    IDA_OEP_ADDR: OEP 地址（十六进制，必填）
    IDA_OUTPUT: 输出文件路径（必填）
    IDA_DEBUG_TIMEOUT: 等待断点超时秒数（默认 60）

level: intermediate
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _base import env_int, env_str, log, run_headless

import ida_auto
import ida_bytes
import ida_dbg
import ida_ida
import ida_idaapi
import ida_segment


def _load_debugger():
    filetype = ida_ida.inf_get_filetype()
    if filetype == ida_ida.f_PE:
        ida_dbg.load_debugger("win32", 0)
        log("[*] 已加载 win32 调试器插件\n")
    elif filetype == ida_ida.f_ELF:
        ida_dbg.load_debugger("linux", 0)
        log("[*] 已加载 linux 调试器插件\n")
    elif filetype == ida_ida.f_MACHO:
        ida_dbg.load_debugger("mac", 0)
        log("[*] 已加载 mac 调试器插件\n")
    else:
        log(f"[!] 不支持的文件类型: {filetype}\n")


def _parse_oep_addr(oep_str):
    try:
        return int(oep_str, 16) if oep_str.startswith("0x") or oep_str.startswith("0X") else int(oep_str)
    except ValueError:
        try:
            return int(oep_str, 16)
        except ValueError:
            return ida_idaapi.BADADDR


def _dump_segments(oep_addr):
    log("[*] 开始 dump 内存段...\n")
    seg = ida_segment.get_first_seg()
    seg_data = []
    while seg.start_ea != ida_idaapi.BADADDR:
        size = seg.end_ea - seg.start_ea
        if size <= 0:
            log(f"[!] 跳过无效段: 0x{seg.start_ea:X} (大小={size})\n")
            seg = ida_segment.get_next_seg(seg.end_ea)
            continue
        log(f"[*] 正在 dump 段: 0x{seg.start_ea:X} - 0x{seg.end_ea:X} ({size} 字节)\n")
        data = ida_bytes.get_bytes(seg.start_ea, size)
        if data is None:
            log(f"[!] 读取段失败: 0x{seg.start_ea:X}\n")
            seg = ida_segment.get_next_seg(seg.end_ea)
            continue
        seg_data.append((seg.start_ea, data))
        seg = ida_segment.get_next_seg(seg.end_ea)
    log(f"[+] dump 完成，共 {len(seg_data)} 个段\n")
    return seg_data


def _rebuild_pe(seg_data, image_base, oep_addr, output_path):
    log("[*] 开始重建 PE 文件...\n")

    dos_header_size = 64
    dos_header = ida_bytes.get_bytes(image_base, dos_header_size)
    if dos_header is None or len(dos_header) < dos_header_size:
        log("[!] 无法读取 DOS header\n")
        return False

    if dos_header[0:2] != b"MZ":
        log("[!] 无效的 DOS 签名\n")
        return False

    e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]
    nt_sig = ida_bytes.get_bytes(image_base + e_lfanew, 4)
    if nt_sig is None or nt_sig != b"PE\x00\x00":
        log("[!] 无效的 PE 签名\n")
        return False

    file_header_offset = e_lfanew + 4
    file_header = ida_bytes.get_bytes(image_base + file_header_offset, 20)
    num_sections = struct.unpack_from("<H", file_header, 2)[0]
    opt_header_size = struct.unpack_from("<H", file_header, 16)[0]

    opt_header_offset = file_header_offset + 20
    opt_header = bytearray(ida_bytes.get_bytes(image_base + opt_header_offset, opt_header_size))

    magic = struct.unpack_from("<H", opt_header, 0)[0]
    is_pe32_plus = (magic == 0x20B)
    log(f"[*] PE 格式: {'PE32+' if is_pe32_plus else 'PE32'}，段数: {num_sections}\n")

    if is_pe32_plus:
        entry_point_off = 16
        image_base_off = 24
        image_base_fmt = "<Q"
    else:
        entry_point_off = 16
        image_base_off = 28
        image_base_fmt = "<I"

    oep_rva = oep_addr - image_base
    struct.pack_into("<I", opt_header, entry_point_off, oep_rva & 0xFFFFFFFF)
    log(f"[*] 已修正入口点 RVA: 0x{oep_rva:X}\n")

    section_table_offset = opt_header_offset + opt_header_size
    section_headers = bytearray(ida_bytes.get_bytes(image_base + section_table_offset, num_sections * 40))

    seg_map = {}
    for start_ea, data in seg_data:
        seg_map[start_ea] = data

    total_raw_size = section_table_offset + num_sections * 40
    raw_offset = total_raw_size

    for i in range(num_sections):
        sec_offset = i * 40
        va = struct.unpack_from("<I", section_headers, sec_offset + 12)[0]
        vsize = struct.unpack_from("<I", section_headers, sec_offset + 8)[0]
        raw_size = (vsize + 0x1FF) & ~0x1FF

        struct.pack_into("<I", section_headers, sec_offset + 16, raw_size)
        struct.pack_into("<I", section_headers, sec_offset + 20, raw_offset)

        total_raw_size = raw_offset + raw_size
        raw_offset = total_raw_size

    output = bytearray(total_raw_size)

    header_copy_size = section_table_offset + num_sections * 40
    header_data = ida_bytes.get_bytes(image_base, header_copy_size)
    if header_data:
        output[0:header_copy_size] = header_data[0:header_copy_size]

    output[opt_header_offset:opt_header_offset + opt_header_size] = opt_header[0:opt_header_size]
    output[section_table_offset:section_table_offset + num_sections * 40] = section_headers[0:num_sections * 40]

    for i in range(num_sections):
        sec_offset = i * 40
        va = struct.unpack_from("<I", section_headers, sec_offset + 12)[0]
        vsize = struct.unpack_from("<I", section_headers, sec_offset + 8)[0]
        raw_off = struct.unpack_from("<I", section_headers, sec_offset + 20)[0]
        raw_sz = struct.unpack_from("<I", section_headers, sec_offset + 16)[0]

        seg_start = image_base + va
        if seg_start in seg_map:
            data = seg_map[seg_start]
            copy_size = min(len(data), raw_sz, vsize)
            output[raw_off:raw_off + copy_size] = data[0:copy_size]
        else:
            log(f"[!] 段 {i} (VA=0x{va:X}) 未找到对应内存数据，填充零\n")

    with open(output_path, "wb") as f:
        f.write(output)

    log(f"[+] PE 文件已写入: {output_path} ({len(output)} 字节)\n")
    log(f"[+] 入口点 RVA: 0x{oep_rva:X}，段数: {num_sections}\n")
    log("[!] 注意: 输出 PE 不含 IAT 重建，仅用于 IDA 加载分析\n")
    return True


class DumpHook(ida_dbg.DBG_Hooks):
    def __init__(self, oep_addr, output_path, image_base):
        ida_dbg.DBG_Hooks.__init__(self)
        self.oep_addr = oep_addr
        self.output_path = output_path
        self.image_base = image_base
        self.result = {"success": False, "error": None, "data": None}

    def dbg_run_to(self, pid, tid=0, ea=0):
        ida_dbg.refresh_debugger_memory()
        is_64 = ida_ida.inf_is_64bit()
        pc = ida_dbg.get_reg_val("RIP" if is_64 else "EIP")
        log(f"[*] 断点命中: PC=0x{pc:X}，目标 OEP=0x{self.oep_addr:X}\n")

        if pc != self.oep_addr:
            log(f"[!] PC 不等于 OEP，继续运行\n")
            ida_dbg.request_continue_process()
            ida_dbg.run_requests()
            return

        seg_data = _dump_segments(self.oep_addr)
        if not seg_data:
            self.result["error"] = "dump 内存段失败"
            ida_dbg.request_exit_process()
            ida_dbg.run_requests()
            return

        success = _rebuild_pe(seg_data, self.image_base, self.oep_addr, self.output_path)
        self.result["success"] = success
        self.result["data"] = {
            "output_path": self.output_path,
            "oep_addr": hex(self.oep_addr),
            "segments_dumped": len(seg_data),
        }
        if not success:
            self.result["error"] = "PE 重建失败"

        ida_dbg.request_exit_process()
        ida_dbg.run_requests()

    def dbg_process_exit(self, pid, tid, ea, code):
        log(f"[*] 调试进程已退出，退出码: {code}\n")
        return 0


def _main():
    oep_str = env_str("IDA_OEP_ADDR", "")
    output_path = env_str("IDA_OUTPUT", "")
    timeout = env_int("IDA_DEBUG_TIMEOUT", 60)

    if not oep_str:
        return {"success": False, "error": "未设置 IDA_OEP_ADDR 环境变量", "data": None}
    if not output_path:
        return {"success": False, "error": "未设置 IDA_OUTPUT 环境变量", "data": None}

    oep_addr = _parse_oep_addr(oep_str)
    if oep_addr == ida_idaapi.BADADDR:
        return {"success": False, "error": f"无效的 OEP 地址: {oep_str}", "data": None}

    image_base = ida_ida.inf_get_baseaddr()
    log(f"[*] OEP: 0x{oep_addr:X}，Image Base: 0x{image_base:X}\n")
    log(f"[*] 输出路径: {output_path}\n")

    _load_debugger()

    hook = DumpHook(oep_addr, output_path, image_base)
    hook.hook()

    log(f"[*] 启动调试器，运行到 OEP: 0x{oep_addr:X}\n")
    ida_dbg.run_to(oep_addr)

    state = ida_dbg.get_process_state()
    while state != 0:
        ida_dbg.wait_for_next_event(1, 0)
        state = ida_dbg.get_process_state()

    hook.unhook()
    return hook.result


run_headless(_main)
