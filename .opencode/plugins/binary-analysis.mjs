import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const DATA_DIR = join(homedir(), "bw-ida-pro-analysis");
const CONFIG_FILE = join(DATA_DIR, "config.json");
const ENV_CACHE_FILE = join(DATA_DIR, "env_cache.json");

const COMPACT_RULES = `## BinaryAnalysis 关键规则（压缩后恢复）

① 禁止作弊式验证 — 必须用 Unicorn/ctypes/Hook/GUI/Patch 验证结果，绝不能用自己代码验证自己
② 技术选型 — 计算密集型用 C/C++（见 knowledge-base/technology-selection.md）
③ ECDLP — 64-bit 以上必须用 C（见 knowledge-base/ecdlp-solving.md）
④ 环境检测 — detect_env.py 检测工具链，缓存 24h
⑤ 静态分析 15 分钟无进展 → 立即切动态分析
⑥ 超时监控 — idat 300s 超时，LLM 60s 无响应反思方案
⑦ 失败快速切换 — 同一方向连续 2 次失败 → 强制换方向
⑧ 不要执着 Python — 什么技术栈适合就用什么`;

function readJsonSafe(filePath) {
  try {
    if (existsSync(filePath)) {
      return JSON.parse(readFileSync(filePath, "utf-8"));
    }
  } catch {}
  return null;
}

export const BinaryAnalysisPlugin = async ({ directory }) => {
  return {
    "experimental.session.compacting": async (input, output) => {
      output.context.push(COMPACT_RULES);
    },

    "experimental.chat.system.transform": async (input, output) => {
      const config = readJsonSafe(CONFIG_FILE);
      if (!config) return;

      const envData = readJsonSafe(ENV_CACHE_FILE);
      const envInfo = envData?.data;

      const scriptsDir = config.scripts_dir || join(directory, ".opencode", "binary-analysis");
      const idaPath = config.ida_path || "未配置";

      let envSection = `\n## BinaryAnalysis 环境信息\n`;
      envSection += `- IDA Pro: ${idaPath}\n`;
      envSection += `- 脚本目录 ($SCRIPTS_DIR): ${scriptsDir}\n`;

      if (envInfo) {
        const compiler = envInfo.compiler;
        if (compiler?.available) {
          envSection += `- 编译器: ${compiler.type} (${compiler.path})\n`;
          if (compiler.vcvarsall) {
            envSection += `- vcvarsall: ${compiler.vcvarsall}\n`;
          }
        } else {
          envSection += `- 编译器: 未检测到\n`;
        }
        if (envInfo.packages) {
          const pkgs = Object.entries(envInfo.packages)
            .filter(([, v]) => v.available)
            .map(([k, v]) => `${k}@${v.version}`)
            .join(", ");
          envSection += `- Python 包: ${pkgs}\n`;
        }
      }

      if (typeof output === "string") {
        output += envSection;
      } else if (output && typeof output === "object") {
        if (Array.isArray(output)) {
          output.push(envSection);
        } else if ("system" in output) {
          output.system = (output.system || "") + envSection;
        }
      }
    },
  };
};
