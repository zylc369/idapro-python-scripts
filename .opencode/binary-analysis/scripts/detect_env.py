"""summary: 跨平台环境自动检测脚本

description:
  检测逆向分析所需的工具链和依赖包，输出 JSON 格式结果。
  支持 Windows/Linux/macOS。
  自动创建专用虚拟环境（~/bw-ida-pro-analysis/.venv），在其中安装 Python 包。
  C/C++ 编译器缺失时通知用户。
  结果缓存 24 小时。
  必需依赖缺失时返回 success: false，Agent 应停止并提示用户安装。

usage:
  python detect_env.py [--output PATH] [--force] [--skip-install]

level: intermediate
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time

CACHE_DIR = os.path.expanduser("~/bw-ida-pro-analysis")
CACHE_FILE = os.path.join(CACHE_DIR, "env_cache.json")
CACHE_TTL = 86400
VENV_DIR = os.path.join(CACHE_DIR, ".venv")

REQUIRED_PACKAGES = {
    "capstone": {"required": True, "pip_name": "capstone"},
    "unicorn": {"required": True, "pip_name": "unicorn"},
    "gmpy2": {"required": True, "pip_name": "gmpy2"},
    "frida": {"required": False, "pip_name": "frida"},
}


def _venv_python_path():
    if os.name == "nt":
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python")


def _ensure_venv():
    venv_python = _venv_python_path()
    if os.path.isfile(venv_python):
        return venv_python

    print(f"[*] 正在创建虚拟环境: {VENV_DIR}")
    try:
        subprocess.run(
            [sys.executable, "-m", "venv", VENV_DIR],
            check=True, timeout=120,
        )
        print(f"[+] 虚拟环境创建成功: {VENV_DIR}")
        return venv_python
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] 创建虚拟环境失败: {e}", file=sys.stderr)
        print(f"[!] 请手动创建: {sys.executable} -m venv {VENV_DIR}", file=sys.stderr)
        return None


def _load_cache(force=False):
    if force:
        return None
    if not os.path.isfile(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            cache = json.load(f)
        if time.time() - cache.get("timestamp", 0) < CACHE_TTL:
            return cache.get("data")
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _save_cache(data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump({"timestamp": time.time(), "data": data}, f, indent=2, ensure_ascii=False)


def _detect_compiler():
    system = platform.system()
    result = {"available": False, "type": None, "path": None, "vcvarsall": None}

    if system == "Windows":
        result = _detect_msvc()
        if not result["available"]:
            result = _detect_gcc_windows()
    elif system == "Darwin":
        result = _detect_clang_macos()
        if not result["available"]:
            result = _detect_gcc_unix()
    else:
        result = _detect_gcc_unix()

    return result


def _safe_listdir(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def _detect_msvc():
    result = {"available": False, "type": None, "path": None, "vcvarsall": None}

    vs_where = shutil.which("vswhere.exe")
    if vs_where:
        try:
            out = subprocess.run(
                [vs_where, "-latest", "-property", "installationPath"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0 and out.stdout.strip():
                vs_path = out.stdout.strip().split("\n")[0].strip()
                vcvarsall = os.path.join(vs_path, "VC", "Auxiliary", "Build", "vcvarsall.bat")
                if os.path.isfile(vcvarsall):
                    cl_path = _find_cl_in_vs(vs_path)
                    result = {
                        "available": True,
                        "type": "msvc",
                        "path": cl_path,
                        "vcvarsall": vcvarsall,
                    }
                    return result
        except (subprocess.TimeoutExpired, OSError):
            pass

    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vs_dir = os.path.join(program_files_x86, "Microsoft Visual Studio")
    if os.path.isdir(vs_dir):
        for version_dir in _safe_listdir(vs_dir):
            version_path = os.path.join(vs_dir, version_dir)
            if not os.path.isdir(version_path):
                continue
            for edition_dir in _safe_listdir(version_path):
                edition_path = os.path.join(version_path, edition_dir)
                vcvarsall = os.path.join(edition_path, "VC", "Auxiliary", "Build", "vcvarsall.bat")
                if os.path.isfile(vcvarsall):
                    cl_path = _find_cl_recursive(
                        os.path.join(edition_path, "VC", "Tools", "MSVC"), "cl.exe"
                    )
                    if not cl_path:
                        cl_path = _find_cl_recursive(edition_path, "cl.exe")
                    return {
                        "available": True,
                        "type": "msvc",
                        "path": cl_path,
                        "vcvarsall": vcvarsall,
                    }

    return result


def _find_cl_in_vs(vs_path):
    msvc_dir = os.path.join(vs_path, "VC", "Tools", "MSVC")
    if not os.path.isdir(msvc_dir):
        return None
    return _find_cl_recursive(msvc_dir, "cl.exe")


def _find_cl_recursive(base_dir, filename):
    if not os.path.isdir(base_dir):
        return None
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.lower() == filename.lower():
                return os.path.join(root, f)
    return None


def _detect_gcc_windows():
    for name in ["gcc.exe", "g++.exe", "clang.exe"]:
        path = shutil.which(name)
        if path:
            return {"available": True, "type": "gcc", "path": path, "vcvarsall": None}
    return {"available": False, "type": None, "path": None, "vcvarsall": None}


def _detect_clang_macos():
    path = shutil.which("clang")
    if path:
        return {"available": True, "type": "clang", "path": path, "vcvarsall": None}
    return {"available": False, "type": None, "path": None, "vcvarsall": None}


def _detect_gcc_unix():
    for name in ["gcc", "g++", "cc"]:
        path = shutil.which(name)
        if path:
            return {"available": True, "type": "gcc", "path": path, "vcvarsall": None}
    return {"available": False, "type": None, "path": None, "vcvarsall": None}


def _detect_package(name, venv_python):
    try:
        result = subprocess.run(
            [venv_python, "-c", f"import {name}; print(__import__('{name}').__version__)"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return {"available": True, "version": result.stdout.strip() or "unknown"}
    except (subprocess.TimeoutExpired, OSError):
        pass
    return {"available": False, "version": None}


def _install_package(venv_python, pip_name, timeout=60):
    pip_cmd = [venv_python, "-m", "pip", "install", pip_name]
    try:
        result = subprocess.run(pip_cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            return True
        print(f"[!] pip install {pip_name} 失败: {result.stderr.strip()}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"[!] pip install {pip_name} 超时 ({timeout}s)", file=sys.stderr)
    except OSError as e:
        print(f"[!] pip install {pip_name} 异常: {e}", file=sys.stderr)
    return False


def _detect_ida_pro():
    config_file = os.path.join(CACHE_DIR, "config.json")
    if not os.path.isfile(config_file):
        return {"available": False, "path": None}
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        ida_path = config.get("ida_path", "")
        idat_name = "idat.exe" if platform.system() == "Windows" else "idat"
        if ida_path and os.path.isfile(os.path.join(ida_path, idat_name)):
            return {"available": True, "path": ida_path}
    except (json.JSONDecodeError, OSError):
        pass
    return {"available": False, "path": None}


def run_detection(skip_install=False):
    errors = []

    print("[*] 正在创建/检测虚拟环境...")
    venv_python = _ensure_venv()
    if venv_python is None:
        errors.append(f"虚拟环境创建失败。请手动运行: {sys.executable} -m venv {VENV_DIR}")
        result = {"success": False, "data": {"venv_python": None, "compiler": {"available": False}, "packages": {}, "ida_pro": {"available": False}}, "errors": errors}
        return result

    print(f"[+] 虚拟环境 Python: {venv_python}")

    print("[*] 正在检测 C/C++ 编译器...")
    compiler = _detect_compiler()
    if compiler["available"]:
        print(f"[+] 编译器: {compiler['type']} — {compiler['path']}")
    else:
        system = platform.system()
        if system == "Windows":
            hint = "请安装 VS Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        elif system == "Darwin":
            hint = "请运行: xcode-select --install"
        else:
            hint = "请运行: sudo apt install build-essential (Debian/Ubuntu) 或 sudo yum groupinstall 'Development Tools' (RHEL/CentOS)"
        msg = f"C/C++ 编译器未找到。{hint}"
        errors.append(msg)
        print(f"[!] {msg}")

    print("[*] 正在检测 Python 架构...")
    python_arch = platform.architecture()[0]
    print(f"[+] Python 架构: {python_arch}")

    packages = {}
    for name, info in REQUIRED_PACKAGES.items():
        print(f"[*] 正在检测 {name}...")
        pkg_info = _detect_package(name, venv_python)
        if not pkg_info["available"] and not skip_install:
            print(f"[*] {name} 未安装，正在自动安装到虚拟环境...")
            if _install_package(venv_python, info["pip_name"]):
                pkg_info = _detect_package(name, venv_python)
                if pkg_info["available"]:
                    print(f"[+] {name} 安装成功: {pkg_info['version']}")
                else:
                    print(f"[!] {name} 安装后仍无法导入")
            else:
                pip_path = os.path.join(os.path.dirname(venv_python), "pip") if os.name != "nt" else os.path.join(os.path.dirname(venv_python), "pip.exe")
                manual_cmd = f"{venv_python} -m pip install {info['pip_name']}"
                if info["required"]:
                    errors.append(f"{name} 安装失败，请手动运行: {manual_cmd}")
                else:
                    print(f"[!] {name} 安装失败（可选包，不影响核心流程）。手动安装: {manual_cmd}")
        elif pkg_info["available"]:
            print(f"[+] {name}: {pkg_info['version']}")
        else:
            if info["required"]:
                manual_cmd = f"{venv_python} -m pip install {info['pip_name']}"
                errors.append(f"{name} 未安装。请运行: {manual_cmd}")
            print(f"[!] {name} 未安装（--skip-install）")
        packages[name] = pkg_info

    print("[*] 正在检测 IDA Pro...")
    ida_pro = _detect_ida_pro()
    if ida_pro["available"]:
        print(f"[+] IDA Pro: {ida_pro['path']}")
    else:
        print("[!] IDA Pro 未配置")

    data = {
        "compiler": compiler,
        "python_arch": python_arch,
        "packages": packages,
        "ida_pro": ida_pro,
        "venv_python": venv_python,
    }

    success = len(errors) == 0
    result = {"success": success, "data": data, "errors": errors}

    _save_cache(data)

    return result


def main():
    parser = argparse.ArgumentParser(description="逆向分析环境检测")
    parser.add_argument("--output", "-o", help="输出 JSON 文件路径")
    parser.add_argument("--force", "-f", action="store_true", help="强制重新检测（忽略缓存）")
    parser.add_argument("--skip-install", action="store_true", help="跳过自动安装缺失的包")
    args = parser.parse_args()

    cached = _load_cache(force=args.force)
    if cached and not args.force:
        venv_python = cached.get("venv_python")
        if venv_python and os.path.isfile(venv_python):
            result = {"success": True, "data": cached, "errors": []}
            print("[*] 使用缓存的环境检测结果（使用 --force 强制重新检测）")
        else:
            print("[!] 缓存中的虚拟环境路径无效，重新检测...")
            cached = None

    if not cached or args.force:
        result = run_detection(skip_install=args.skip_install)

    output_json = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"\n[+] 结果已写入: {args.output}")
    else:
        print(f"\n{output_json}")

    if not result["success"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
