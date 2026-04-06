#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CALL_DIR="$(pwd)"
REPO_ROOT="${REPO_ROOT:-"$(cd "$SCRIPT_DIR/.." && pwd)"}"
readonly PYTHON_SCRIPT="$SCRIPT_DIR/dump_func_disasm.py"
readonly DEFAULT_LOG_FILENAME="dump_func_disasm.log"

source "$SCRIPT_DIR/../shell/library/detect_ida_path.sh"
source "$SCRIPT_DIR/../shell/library/detect_db_lock.sh"

addr=""
output=""
log_path=""
input_file=""
ida_path=""

print_usage() {
    cat >&2 << EOF
用法: $(basename "$0") --addr <函数名或地址> --input <目标文件> [选项]

必填参数:
  --addr   <值>   函数名（如 main）或十六进制地址（如 0x401000）
  --input  <路径>  目标二进制文件或 .i64 数据库路径

可选参数:
  --output <路径>  输出文件或目录路径（默认: 当前执行目录）
  --log    <路径>  日志文件路径（默认: 当前执行目录/dump_func_disasm.log）
  --ida-path <路径> IDA Pro 安装目录路径（默认: 自动检测）
  -h, --help       显示此帮助信息

示例:
  $(basename "$0") --addr main --input /path/to/binary.i64
  $(basename "$0") --addr 0x401000 --output /tmp/out.asm --input /path/to/binary.i64
  $(basename "$0") --addr main --ida-path /opt/ida --input /path/to/binary.i64
EOF
}

print_usage() {
    echo "用法: $(basename "$0") [选项]"
    echo ""
    echo "选项:"
    echo "  --addr <函数名或地址>     必填，函数名或十六进制地址"
    echo "  --input <文件路径>    必填，目标二进制或 .i64/.idb 文件路径"
    echo "  --output <路径>          可选， 输出文件或目录路径 (默认: 当前执行目录)"
    echo "  --log <路径>             可选， idat 日志文件路径 (默认: 当前执行目录/dump_func_disasm.log)"
    echo "  --ida-path <路径>        可选， IDA Pro 安装目录路径 (默认: 自动检测)"
    echo "  -h, --help              显示此帮助信息"
}


parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -a|--addr)
                addr="$2"
                shift 2
                ;;
            -o|--output)
                output="$2"
                shift 2
                ;;
            -l|--log)
                log_path="$2"
                shift 2
                ;;
            -i|--input)
                input_file="$2"
                shift 2
                ;;
            -p|--ida-path)
                ida_path="$2"
                shift 2
                ;;
            -h|--help)
                print_usage
                return 0
                ;;
            -*)
                echo "[!] 错误: 未知选项 $1" >&2
                print_usage >&2
                return 1
                ;;
            *)
                echo "[!] 错误: 未知参数 $1" >&2
                print_usage
                return 1
                ;;
        esac
    done
}

validate_inputs() {
    if [[ -z "$addr" ]]; then
        echo "[!] 错误: 必须指定 --addr 参数" >&2
        return 1
    fi
    if [[ -z "$input_file" ]]; then
        echo "[!] 错误: 必须指定 --input 参数" >&2
        return 1
    fi
    if [[ ! -f "$input_file" ]]; then
        echo "[!] 错误: 目标文件不存在: $input_file" >&2
        return 1
    fi
}

resolve_paths() {
    input_file="$(cd "$(dirname "$input_file")" && pwd)/$(basename "$input_file")"

    if [[ -z "$output" ]]; then
        output="$CALL_DIR"
    fi
    if [[ "$output" != /* ]]; then
        output="$CALL_DIR/$output"
    fi

    if [[ -z "$log_path" ]]; then
        log_path="$CALL_DIR/$DEFAULT_LOG_FILENAME"
    fi
    if [[ "$log_path" != /* ]]; then
        log_path="$CALL_DIR/$log_path"
    fi
}

execute_idat() {
    local ida_dir
    ida_dir=$(detect_ida_path "${ida_path:-}") || return 1

    check_db_lock "$input_file" || return 1

    mkdir -p "$(dirname "$output")"
    mkdir -p "$(dirname "$log_path")"

    echo "[*] 正在执行 idat 反汇编..." >&2
    echo "[*] 函数: $addr" >&2
    echo "[*] 输出: $output" >&2
    echo "[*] 日志: $log_path" >&2
    echo "[*] 目标: $input_file" >&2

    local exit_code=0
    IDA_FUNC_ADDR="$addr" \
    IDA_OUTPUT="$output" \
    "$ida_dir/idat" -v -A \
        -L"$log_path" \
        -S"$PYTHON_SCRIPT" \
        "$input_file" || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo "[+] idat 执行成功 (exit code: 0)" >&2
    else
        echo "[!] idat 执行失败 (exit code: $exit_code)" >&2
    fi
    echo "[*] 日志文件: $log_path" >&2

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
