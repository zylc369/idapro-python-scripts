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

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _base import env_int, env_str, log, run_headless
from _analysis import (
    classify_scene,
    collect_entry_points,
    collect_imports,
    collect_segments,
    collect_strings,
    detect_packer,
)

import ida_funcs


def _main():
    segments, packer_name_from_seg, packer_conf = collect_segments()
    entries, file_type, architecture, bits = collect_entry_points()
    modules, total_functions, import_names = collect_imports()

    pattern = env_str("IDA_STRINGS_PATTERN", "")
    max_strings = env_int("IDA_MAX_STRINGS", 200)
    strings = collect_strings(pattern, max_strings)

    func_count = ida_funcs.get_func_qty()
    packer_info = detect_packer(segments, packer_name_from_seg, entries, total_functions)
    scene = classify_scene(packer_info, strings, import_names, architecture, file_type)

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
