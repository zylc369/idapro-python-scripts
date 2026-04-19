# -*- coding: utf-8 -*-
"""summary: 一键初始分析流水线

description:
  在单次 idat 调用内完成信息收集和场景分类，替代多次独立 query.py 调用。
  输出结构化 JSON，包含：segments、entry_points、imports、strings、packer_detect、
  以及自动生成的场景分类建议和推荐下一步操作。

  使用方式（idat headless）：
    IDA_OUTPUT=/tmp/result.json \
      idat -A -S"scripts/initial_analysis.py" -L/tmp/initial.log target.i64

  环境变量：
    IDA_OUTPUT: 输出文件路径（必填）
    IDA_STRINGS_PATTERN: 可选，过滤字符串的子串模式（默认返回全部）
    IDA_MAX_STRINGS: 可选，最大字符串数量（默认 200）

level: intermediate
"""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _base import env_int, env_str, log, run_headless

import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_loader
import ida_nalt
import ida_segment
import idautils


_PACKER_SEGMENT_PATTERNS = {
    "UPX": ["UPX", ".upx"],
    "MPRESS": [".nsp0", ".nsp1", ".nsp2"],
    "Themida": [".themida", ".winlice"],
    "VMProtect": [".vmp0", ".vmp1"],
    "ASPack": [".aspack"],
    "PECompact": [".pec2"],
    "Enigma": [".enigma1", ".enigma2"],
}


def _seg_perm_str(perm):
    s = ""
    if perm & 1:
        s += "x"
    if perm & 2:
        s += "w"
    if perm & 4:
        s += "r"
    return s


def _hex_addr(ea):
    return f"0x{ea:X}"


def _collect_segments():
    log("[*] [1/5] 正在收集段信息...\n")
    seg_list = []
    packer_name = None
    packer_confidence = "none"
    total_size = 0

    qty = ida_segment.get_segm_qty()
    for i in range(qty):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        total_size += seg.end_ea - seg.start_ea

    for i in range(qty):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        name = ida_segment.get_segm_name(seg)
        size = seg.end_ea - seg.start_ea
        anomaly_hints = []

        name_upper = name.upper()
        for packer, patterns in _PACKER_SEGMENT_PATTERNS.items():
            for pat in patterns:
                if name_upper.startswith(pat.upper()):
                    anomaly_hints.append(f"known_packer_segment:{packer}")
                    if packer_confidence != "high":
                        packer_name = packer
                        packer_confidence = "high"
                    break

        if total_size > 0 and size > total_size * 0.9:
            anomaly_hints.append("oversized_segment")

        seg_list.append({
            "name": name,
            "start": _hex_addr(seg.start_ea),
            "end": _hex_addr(seg.end_ea),
            "size": size,
            "perm": _seg_perm(seg.perm),
            "anomaly_hints": anomaly_hints,
        })

    log(f"[+] 段信息收集完成: {len(seg_list)} 个段\n")
    return seg_list, packer_name, packer_confidence


def _collect_entry_points():
    log("[*] [2/5] 正在收集入口点...\n")
    entries = []
    seen = set()

    proc_name = ida_ida.inf_get_procname()
    arch_map = {
        "metapc": "x86",
        "ARM": "arm",
        "ARM64": "arm64",
        "aarch64": "arm64",
    }
    architecture = arch_map.get(proc_name, proc_name)

    bits = None
    if architecture == "x86":
        if ida_ida.inf_is_64bit():
            bits = 64
        elif ida_ida.inf_is_32bit_exactly():
            bits = 32
        else:
            bits = 16
    elif architecture == "arm64":
        bits = 64
    elif architecture == "arm":
        bits = 32

    file_type_name = ida_loader.get_file_type_name().lower()
    if "dll" in file_type_name:
        file_type = "dll"
    elif "so" in file_type_name or "elf" in file_type_name:
        file_type = "so"
    elif "exe" in file_type_name:
        file_type = "exe"
    elif "macho" in file_type_name:
        file_type = "macho"
    else:
        file_type = "unknown"

    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ordinal = ida_entry.get_entry_ordinal(i)
        addr = ida_entry.get_entry(ordinal)
        if addr in seen:
            continue
        seen.add(addr)
        name = ida_entry.get_entry_name(ordinal)
        if not name:
            name = f"entry_{ordinal}"

        name_lower = name.lower()
        if name.startswith("."):
            etype = "init_array"
        elif name_lower in ("main", "_main", "wmain", "winmain", "wwinmain",
                            "dllmain", "driverentry"):
            etype = "main"
        elif "jni" in name_lower:
            etype = "jni"
        elif name_lower in ("_init", "init", ".init"):
            etype = "init"
        elif name_lower in ("_start", "start"):
            etype = "crt_entry"
        elif name_lower in ("_fini", "fini", ".fini"):
            etype = "fini"
        else:
            etype = "entry"

        entries.append({
            "name": name,
            "addr": _hex_addr(addr),
            "type": etype,
            "ordinal": ordinal,
        })

    log(f"[+] 入口点收集完成: {len(entries)} 个\n")
    return entries, file_type, architecture, bits


def _collect_imports():
    log("[*] [3/5] 正在收集导入表...\n")
    modules = []
    total_functions = 0
    import_names_set = set()

    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name:
            mod_name = f"module_{i}"
        funcs = []

        def _import_cb(ea, name, ordinal):
            nonlocal total_functions
            actual_name = name if name else f"ord_{ordinal}"
            funcs.append({"name": actual_name, "addr": _hex_addr(ea), "ordinal": ordinal})
            import_names_set.add(actual_name)
            total_functions += 1
            return True

        ida_nalt.enum_import_names(i, _import_cb)
        if funcs:
            modules.append({"module": mod_name, "functions": funcs, "count": len(funcs)})

    log(f"[+] 导入表收集完成: {len(modules)} 个模块, {total_functions} 个函数\n")
    return modules, total_functions, import_names_set


def _collect_strings(pattern="", max_count=200):
    log(f"[*] [4/5] 正在收集字符串 (pattern='{pattern}', max={max_count})...\n")
    strings_list = []
    for i, s in enumerate(idautils.Strings(False)):
        if len(strings_list) >= max_count:
            break
        value = str(s)
        if pattern and pattern.lower() not in value.lower():
            continue
        ea = s.ea
        xrefs = []
        for xref in idautils.XrefsTo(ea, 0):
            func = ida_funcs.get_func(xref.frm)
            func_name = ida_funcs.get_func_name(xref.frm) if func else ""
            xrefs.append({"from": _hex_addr(xref.frm), "func": func_name})
            if len(xrefs) >= 10:
                break
        strings_list.append({
            "value": value,
            "addr": _hex_addr(ea),
            "length": len(value),
            "xrefs": xrefs,
        })

    log(f"[+] 字符串收集完成: {len(strings_list)} 个\n")
    return strings_list


def _estimate_entropy(ea, size):
    if size <= 0 or size > 1048576:
        return 0.0
    sample_size = min(size, 1024)
    freq = [0] * 256
    for i in range(sample_size):
        b = ida_bytes.get_byte(ea + i)
        freq[b] += 1
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / sample_size
            entropy -= p * math.log2(p)
    return entropy


def _detect_packer(segments, packer_name_from_seg, entry_points, import_count):
    log("[*] [5/5] 正在执行加壳检测...\n")
    signals = []

    if packer_name_from_seg:
        signals.append({
            "type": "segment_name_match",
            "detail": f"已知壳段名: {packer_name_from_seg}",
            "weight": "high",
        })

    func_count = ida_funcs.get_func_qty()
    ep_count = len(entry_points)
    if func_count <= 2 and ep_count > 0:
        signals.append({
            "type": "function_count",
            "detail": f"仅 {func_count} 个函数但存在 {ep_count} 个入口点",
            "weight": "high",
        })
    elif func_count <= 5 and ep_count > 0:
        signals.append({
            "type": "function_count",
            "detail": f"仅 {func_count} 个函数",
            "weight": "medium",
        })

    if import_count == 0:
        signals.append({
            "type": "import_count",
            "detail": "无导入函数",
            "weight": "high",
        })
    elif import_count <= 3:
        signals.append({
            "type": "import_count",
            "detail": f"仅 {import_count} 个导入函数",
            "weight": "medium",
        })

    for seg in segments:
        if seg["size"] >= 64:
            ea = int(seg["start"], 16)
            entropy = _estimate_entropy(ea, seg["size"])
            if entropy > 7.0:
                signals.append({
                    "type": "high_entropy",
                    "detail": f"段 {seg['name']} 熵={entropy:.2f}",
                    "weight": "medium",
                })

    high_count = sum(1 for s in signals if s["weight"] == "high")
    medium_count = sum(1 for s in signals if s["weight"] == "medium")

    if packer_name_from_seg:
        confidence = "high"
        detected_name = packer_name_from_seg
    elif high_count >= 2:
        confidence = "high"
        detected_name = "unknown"
    elif high_count >= 1 and medium_count >= 1:
        confidence = "medium"
        detected_name = "unknown"
    elif medium_count >= 2:
        confidence = "low"
        detected_name = "unknown"
    else:
        confidence = "none"
        detected_name = None

    packer_detected = confidence in ("high", "medium")

    if packer_detected:
        log(f"[+] 加壳检测: 已检测到加壳 (置信度={confidence}, 壳={detected_name})\n")
    else:
        log(f"[+] 加壳检测: 未检测到加壳\n")

    return {
        "packer_detected": packer_detected,
        "confidence": confidence,
        "packer_name": detected_name,
        "signals": signals,
    }


def _classify_scene(packer_info, strings, import_names, architecture, file_type):
    log("[*] 正在进行场景分类...\n")
    scene_tags = []
    recommended_actions = []
    knowledge_base_loads = []

    if packer_info["packer_detected"]:
        scene_tags.append("packed")
        recommended_actions.append({
            "action": "unpack",
            "priority": 1,
            "description": "二进制已加壳，优先脱壳",
            "detail": f"壳类型: {packer_info.get('packer_name', 'unknown')}，置信度: {packer_info['confidence']}",
        })
        knowledge_base_loads.append("packer-handling.md")

    crypto_signals = []
    string_values = " ".join(s["value"] for s in strings)
    if "0123456789ABCDEF" in string_values or "0123456789abcdef" in string_values:
        crypto_signals.append("hex_table")
    if "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in string_values:
        crypto_signals.append("base64_table")

    crypto_imports = []
    for name in import_names:
        if any(kw in name.lower() for kw in ["crypt", "hash", "md5", "sha", "aes", "rsa", "des", "cipher"]):
            crypto_imports.append(name)

    if crypto_signals or crypto_imports:
        scene_tags.append("crypto")
        recommended_actions.append({
            "action": "crypto_analysis",
            "priority": 2 if "packed" not in scene_tags else 3,
            "description": "检测到密码学特征，加载密码学识别文档",
            "detail": f"信号: {crypto_signals + crypto_imports}",
        })
        knowledge_base_loads.append("crypto-validation-patterns.md")

    gui_indicators = []
    for name in import_names:
        if any(kw in name for kw in [
            "CreateWindow", "DialogBox", "MessageBox", "SetDlgItemText",
            "GetDlgItemText", "ShowWindow", "SendMessage", "PostMessage",
        ]):
            gui_indicators.append(name)

    if gui_indicators:
        scene_tags.append("gui")
        recommended_actions.append({
            "action": "gui_interaction",
            "priority": 2 if "packed" not in scene_tags else 4,
            "description": "检测到 GUI 程序，可能需要动态交互",
            "detail": f"GUI API: {gui_indicators[:10]}",
        })
        knowledge_base_loads.append("dynamic-analysis.md")

    error_strings = [s for s in strings if any(
        kw in s["value"].lower()
        for kw in ["error", "fail", "wrong", "invalid", "incorrect", "denied"]
    )]
    if error_strings:
        recommended_actions.append({
            "action": "error_message_analysis",
            "priority": 2 if "packed" not in scene_tags else 3,
            "description": "发现错误提示字符串，可用于定位关键比较逻辑",
            "detail": f"示例: {[s['value'][:50] for s in error_strings[:5]]}",
        })

    if not scene_tags:
        scene_tags.append("standard")

    recommended_actions.sort(key=lambda a: a["priority"])

    log(f"[+] 场景分类: {scene_tags}\n")
    log(f"[+] 推荐操作数: {len(recommended_actions)}\n")

    return {
        "scene_tags": scene_tags,
        "recommended_actions": recommended_actions,
        "knowledge_base_loads": list(dict.fromkeys(knowledge_base_loads)),
        "crypto_signals": crypto_signals,
        "gui_indicators": gui_indicators,
        "error_strings_count": len(error_strings),
    }


def _main():
    segments, packer_name_from_seg, packer_conf = _collect_segments()
    entries, file_type, architecture, bits = _collect_entry_points()
    modules, total_functions, import_names = _collect_imports()

    pattern = env_str("IDA_STRINGS_PATTERN", "")
    max_strings = env_int("IDA_MAX_STRINGS", 200)
    strings = _collect_strings(pattern, max_strings)

    func_count = ida_funcs.get_func_qty()
    packer_info = _detect_packer(segments, packer_name_from_seg, entries, total_functions)

    scene = _classify_scene(packer_info, strings, import_names, architecture, file_type)

    log("[+] 初始分析流水线完成\n")

    return {
        "success": True,
        "data": {
            "segments": {
                "list": segments,
                "total": len(segments),
            },
            "entry_points": {
                "entries": entries,
                "file_type": file_type,
                "architecture": architecture,
                "bits": bits,
                "total": len(entries),
            },
            "imports": {
                "modules": modules,
                "total_functions": total_functions,
            },
            "strings": {
                "list": strings,
                "total": len(strings),
                "pattern": pattern,
            },
            "packer_detect": packer_info,
            "scene": scene,
            "stats": {
                "function_count": func_count,
                "segment_count": len(segments),
                "import_count": total_functions,
                "string_count": len(strings),
                "entry_point_count": len(entries),
            },
        },
        "error": None,
    }


run_headless(_main)
