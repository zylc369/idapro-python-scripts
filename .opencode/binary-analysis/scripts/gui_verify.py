"""summary: Win32 GUI 自动化验证脚本

description:
  自动化操作 Win32 GUI 对话框，输入用户名和 license，点击验证按钮，读取结果。
  仅支持 Windows 平台。通过 Win32 API (ctypes) 实现，无需额外依赖。
  不同程序的控件 ID 不同，支持 --edit1-id/--edit2-id/--button-id 参数覆盖。

usage:
  python gui_verify.py --exe TARGET.EXE --username "test" --license "XXXX" --output result.json
  python gui_verify.py --exe TARGET.EXE --username "test" --license "XXXX" --edit1-id 1001 --edit2-id 1002 --button-id 1003

level: intermediate
"""

import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
import threading

if sys.platform != "win32":
    print(json.dumps({"success": False, "error": "gui_verify.py 仅支持 Windows 平台"}))
    sys.exit(1)

import ctypes.wintypes

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

FindWindowW = user32.FindWindowW
FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
FindWindowW.restype = ctypes.wintypes.HWND

GetDlgItem = user32.GetDlgItem
GetDlgItem.argtypes = [ctypes.wintypes.HWND, ctypes.c_int]
GetDlgItem.restype = ctypes.wintypes.HWND

SendMessageW = user32.SendMessageW
SendMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.c_uint, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
SendMessageW.restype = ctypes.wintypes.LPARAM

PostMessageW = user32.PostMessageW
PostMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.c_uint, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
PostMessageW.restype = ctypes.c_bool

EnumWindows = user32.EnumWindows
EnumWindows.argtypes = [ctypes.c_void_p, ctypes.wintypes.LPARAM]
EnumWindows.restype = ctypes.wintypes.BOOL

GetWindowTextW = user32.GetWindowTextW
GetWindowTextW.argtypes = [ctypes.wintypes.HWND, ctypes.c_wchar_p, ctypes.c_int]
GetWindowTextW.restype = ctypes.c_int

GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(ctypes.wintypes.DWORD)]
GetWindowThreadProcessId.restype = ctypes.wintypes.DWORD

WM_SETTEXT = 0x000C
WM_COMMAND = 0x0111
BM_CLICK = 0x00F5
BN_CLICKED = 0

DEFAULT_EDIT1_ID = 1000
DEFAULT_EDIT2_ID = 1001
DEFAULT_BUTTON_ID = 1002

MB_RESULT_MAP = {
    1: "OK",
    2: "Cancel",
    6: "Retry",
    7: "Close",
    10: "Try Again",
    11: "Continue",
}

_enum_result = {"window_handle": None, "window_text": None, "pid": None}


def _enum_windows_proc(hwnd, lparam):
    target_pid = lparam
    pid = ctypes.wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == target_pid:
        text = ctypes.create_unicode_buffer(512)
        GetWindowTextW(hwnd, text, 512)
        if text.value:
            _enum_result["window_handle"] = hwnd
            _enum_result["window_text"] = text.value
            _enum_result["pid"] = pid.value
            return False
    return True


def _find_main_window(pid, timeout=10):
    deadline = time.time() + timeout
    CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    callback = CMPFUNC(_enum_windows_proc)

    while time.time() < deadline:
        _enum_result["window_handle"] = None
        _enum_result["window_text"] = None
        _enum_result["pid"] = None
        EnumWindows(callback, ctypes.wintypes.LPARAM(pid))
        if _enum_result["window_handle"]:
            return _enum_result["window_handle"], _enum_result["window_text"]
        time.sleep(0.5)
    return None, None


def _find_messagebox(pid, timeout=10):
    deadline = time.time() + timeout
    CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
    callback = CMPFUNC(_enum_windows_proc)

    while time.time() < deadline:
        _enum_result["window_handle"] = None
        _enum_result["window_text"] = None
        _enum_result["pid"] = None
        EnumWindows(callback, ctypes.wintypes.LPARAM(pid))
        if _enum_result["window_handle"] and _enum_result["window_text"]:
            title_lower = _enum_result["window_text"].lower()
            if any(kw in title_lower for kw in ["success", "correct", "right", "ok", "congratulat",
                                                  "fail", "wrong", "error", "invalid", "incorrect"]):
                return _enum_result["window_text"]
        time.sleep(0.3)
    return None


def _set_text(hwnd, text):
    SendMessageW(hwnd, WM_SETTEXT, 0, ctypes.c_wchar_p(text))
    time.sleep(0.1)


def _click_button(parent_hwnd, button_hwnd):
    ctrl_id = user32.GetWindowLongPtrW(button_hwnd, -12)
    if ctrl_id == 0:
        ctrl_id = user32.GetDlgCtrlID(button_hwnd)
    PostMessageW(parent_hwnd, WM_COMMAND, (BN_CLICKED << 16) | ctrl_id, button_hwnd)
    time.sleep(0.2)


def run_verify(exe_path, username, license_code, edit1_id, edit2_id, button_id, timeout):
    if not os.path.isfile(exe_path):
        return {"success": False, "error": f"可执行文件不存在: {exe_path}"}

    print(f"[*] 启动目标进程: {exe_path}")
    try:
        proc = subprocess.Popen([exe_path])
    except OSError as e:
        return {"success": False, "error": f"启动失败: {e}"}

    pid = proc.pid
    print(f"[*] 进程 PID: {pid}")

    try:
        print(f"[*] 等待主窗口出现（超时 {timeout}s）...")
        main_wnd, wnd_text = _find_main_window(pid, timeout=timeout)
        if not main_wnd:
            return {"success": False, "error": "未找到主窗口", "pid": pid}

        print(f"[+] 找到主窗口: {wnd_text}")

        edit1 = GetDlgItem(main_wnd, edit1_id)
        edit2 = GetDlgItem(main_wnd, edit2_id)
        button = GetDlgItem(main_wnd, button_id)

        if not edit1:
            return {"success": False, "error": f"未找到编辑框1 (ID={edit1_id})", "pid": pid}
        if not edit2:
            return {"success": False, "error": f"未找到编辑框2 (ID={edit2_id})", "pid": pid}
        if not button:
            return {"success": False, "error": f"未找到按钮 (ID={button_id})", "pid": pid}

        print(f"[*] 输入用户名: {username}")
        _set_text(edit1, username)

        print(f"[*] 输入 License: {license_code}")
        _set_text(edit2, license_code)

        print("[*] 点击验证按钮...")
        _click_button(main_wnd, button)

        print(f"[*] 等待结果对话框（超时 {timeout}s）...")
        result_text = _find_messagebox(pid, timeout=timeout)

        if result_text:
            print(f"[+] 结果对话框: {result_text}")
            success_keywords = ["success", "correct", "right", "congratulat", "ok", "注册成功", "验证成功", "正确"]
            is_success = any(kw in result_text.lower() for kw in success_keywords)
            return {
                "success": True,
                "verification_passed": is_success,
                "message": result_text,
                "pid": pid,
            }
        else:
            print("[!] 未检测到结果对话框（超时）")
            return {"success": False, "error": "未检测到结果对话框", "pid": pid}

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Win32 GUI 自动化验证")
    parser.add_argument("--exe", required=True, help="目标可执行文件路径")
    parser.add_argument("--username", required=True, help="用户名")
    parser.add_argument("--license", required=True, help="License 代码")
    parser.add_argument("--output", "-o", help="输出 JSON 文件路径")
    parser.add_argument("--timeout", type=int, default=30, help="超时秒数（默认 30）")
    parser.add_argument("--edit1-id", type=int, default=DEFAULT_EDIT1_ID, help="用户名编辑框控件 ID")
    parser.add_argument("--edit2-id", type=int, default=DEFAULT_EDIT2_ID, help="License 编辑框控件 ID")
    parser.add_argument("--button-id", type=int, default=DEFAULT_BUTTON_ID, help="验证按钮控件 ID")
    args = parser.parse_args()

    result = run_verify(
        args.exe, args.username, args.license,
        args.edit1_id, args.edit2_id, args.button_id, args.timeout
    )

    output_json = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"\n[+] 结果已写入: {args.output}")
    else:
        print(f"\n{output_json}")

    if not result.get("verification_passed", False):
        sys.exit(1)


if __name__ == "__main__":
    main()
