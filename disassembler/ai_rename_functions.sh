#!/usr/bin/env bash
# 本文件是 ai_rename_functions.py 的 shell wrapper，存在原因如下：
#
# 1. ai_rename_functions.py 依赖 ida_funcs、ida_kernwin 等 IDAPython 专有模块，
#    无法在终端中直接用 python 执行，只能由 idat（IDA 命令行版本）加载运行。
#
# 2. 直接手写 idat 命令行非常繁琐：
#      IDA_PATTERN="sub_123*" \
#        /opt/ida/idat -A -S"ai_rename_functions.py" -L"/tmp/log" target.i64
#    还需要自己处理 IDA 安装路径检测、数据库锁检测、相对路径转绝对路径等。
#
# 3. 因此 .sh 作为运维胶水层，将这些脏活封装起来，用户只需：
#      ./ai_rename_functions.sh --pattern "sub_123*" --input target.i64
#
# 总结：.py 做业务逻辑（AI 辅助重命名），.sh 做运维胶水（构造 idat 命令行），
# 最终 .sh 通过 `idat -S"$PYTHON_SCRIPT"` 调用 .py，.py 通过环境变量读取参数。
#
# 注意：.py 本身也支持在 IDA GUI 内以对话框/CLI 模式独立使用，
# .sh 只覆盖了其中的 headless（idat 命令行）模式。
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CALL_DIR="$(pwd)"
REPO_ROOT="${REPO_ROOT:-"$(cd "$SCRIPT_DIR/.." && pwd)"}"
readonly PYTHON_SCRIPT="$SCRIPT_DIR/ai_rename_functions.py"
readonly DEFAULT_LOG_FILENAME="ai_rename_functions.log"

source "$SCRIPT_DIR/../shell/library/detect_ida_path.sh"
source "$SCRIPT_DIR/../shell/library/detect_db_lock.sh"
source "$SCRIPT_DIR/../shell/library/log.sh"

pattern=""
dry_run=""
recursive=""
max_depth=""
log_path=""
input_file=""
ida_path=""

print_usage() {
    cat >&2 << EOF
用法: $(basename "$0") --pattern <函数名或模式> --input <目标文件> [选项]

必填参数:
  -p, --pattern    <值>   函数名（如 main）或通配符模式（如 sub_123*）
  -i, --input      <路径>  目标二进制文件或 .i64 数据库路径

可选参数:
  -r, --recursive         递归分析目标函数调用的自动命名函数（sub_XXXXX）
      --max-depth <N>     递归最大深度（默认: 2）
  -l, --log        <路径>  日志文件路径（默认: 当前执行目录/ai_rename_functions.log）
      --ida-path   <路径>  IDA Pro 安装目录路径（默认: 自动检测）
      --dry-run            仅预览 AI 建议，不实际重命名
  -h, --help               显示此帮助信息

示例:
  $(basename "$0") --pattern "main_0" --input binary.i64 --recursive
  $(basename "$0") -p "sub_123*" -i binary.i64 --dry-run
  $(basename "$0") -p "sub_*" -i binary.i64 -r --max-depth 3
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--pattern)
                pattern="$2"
                shift 2
                ;;
            -r|--recursive)
                recursive="1"
                shift
                ;;
            --max-depth)
                max_depth="$2"
                shift 2
                ;;
            -i|--input)
                input_file="$2"
                shift 2
                ;;
            -l|--log)
                log_path="$2"
                shift 2
                ;;
            --ida-path)
                ida_path="$2"
                shift 2
                ;;
            --dry-run)
                dry_run="1"
                shift
                ;;
            -h|--help)
                print_usage
                return 0
                ;;
            *)
                log_error "未知选项 $1"
                print_usage >&2
                return 1
                ;;
        esac
    done
}

validate_inputs() {
    if [[ -z "$pattern" ]]; then
        log_error "必须指定 --pattern 参数"
        return 1
    fi
    if [[ -z "$input_file" ]]; then
        log_error "必须指定 --input 参数"
        return 1
    fi
    if [[ ! -f "$input_file" ]]; then
        log_error "目标文件不存在: $input_file"
        return 1
    fi
}

resolve_paths() {
    input_file="$(cd "$(dirname "$input_file")" && pwd)/$(basename "$input_file")"

    if [[ -z "$log_path" ]]; then
        log_path="$CALL_DIR/$DEFAULT_LOG_FILENAME"
    fi
    if [[ "$log_path" != /* ]]; then
        log_path="$CALL_DIR/$log_path"
    fi
}

_display_results() {
    local log_file="$1"
    if [[ ! -f "$log_file" ]]; then
        log_warn "日志文件不存在: $log_file"
        return
    fi

    local result_lines
    result_lines=$(grep -E \
        '\[预览-|\[\+\] (函数|局部变量|全局数据|结构体字段)重命名|\[\+\] (汇编注释|函数摘要|行内注释|伪代码注释)|\[\+\] 总计:|\[\+\] AI 分析完成|\[!\].*不合法|\[!\].*失败|\[!\].*无法解析|\[!\].*重命名失败|\[!\].*符号表|\[!\].*调试符号|\[!\].*用户或|\[\*\] 理由:|\[\*\] AI 分析结果|\[\*\] 函数重命名:' \
        "$log_file" 2>/dev/null || true)

    if [[ -z "$result_lines" ]]; then
        return
    fi

    log_info "===== 分析结果 ====="
    while IFS= read -r line; do
        line="${line#[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9]* }"
        if [[ -n "$line" ]]; then
            log_info "  ${line}"
        fi
    done <<< "$result_lines"
}

execute_idat() {
    local ida_dir
    ida_dir=$(detect_ida_path "${ida_path:-}") || return 1

    check_db_lock "$input_file" || return 1

    mkdir -p "$(dirname "$log_path")"
    : > "$log_path"

    log_info "正在执行 AI 辅助函数重命名..."
    log_info "模式: $pattern"
    log_info "目标: $input_file"
    log_info "日志: $log_path"
    log_info "递归: $([ -n "$recursive" ] && echo "是 (深度: ${max_depth:-2})" || echo "否")"
    log_info "仅预览: $([ -n "$dry_run" ] && echo "是" || echo "否")"

    local exit_code=0
    IDA_PATTERN="$pattern" \
    IDA_DRY_RUN="${dry_run:-}" \
    IDA_RECURSIVE="${recursive:-}" \
    IDA_MAX_DEPTH="${max_depth:-}" \
    "$ida_dir/idat" -v -A \
        -L"$log_path" \
        -S"$PYTHON_SCRIPT" \
        "$input_file" || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_info "idat 执行成功 (exit code: 0)"
    else
        log_error "idat 执行失败 (exit code: $exit_code)"
    fi
    log_debug "日志文件: $log_path"

    _display_results "$log_path"

    return $exit_code
}

main() {
    parse_args "$@" || return 1
    validate_inputs || return 1
    resolve_paths
    execute_idat
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
