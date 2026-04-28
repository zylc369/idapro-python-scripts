import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";

const DATA_DIR = join(homedir(), "bw-ida-pro-analysis");
const CONFIG_FILE = join(DATA_DIR, "config.json");
const ENV_CACHE_FILE = join(DATA_DIR, "env_cache.json");
const WORKSPACE_DIR = join(DATA_DIR, "workspace");
const TASK_SESSIONS_DIR = join(WORKSPACE_DIR, ".task_sessions");
const DEBUG_LOG = join(DATA_DIR, "plugin_debug.log");
const MAX_LOG_SIZE = 5 * 1024 * 1024;
const KEEP_SIZE = 2 * 1024 * 1024;

function debugLog(msg) {
  try {
    mkdirSync(dirname(DEBUG_LOG), { recursive: true });
    // 超过 5MB 时截断：丢弃最早的日志，只保留最后 2MB
    try {
      if (existsSync(DEBUG_LOG) && statSync(DEBUG_LOG).size > MAX_LOG_SIZE) {
        const content = readFileSync(DEBUG_LOG, "utf-8");
        const keep = content.slice(-KEEP_SIZE);
        const firstNewline = keep.indexOf("\n");
        writeFileSync(DEBUG_LOG, firstNewline >= 0 ? keep.slice(firstNewline + 1) : keep);
      }
    } catch {}
    const ts = new Date().toISOString();
    writeFileSync(DEBUG_LOG, `[${ts}] ${msg}\n`, { flag: "a" });
  } catch {}
}

const COMPACT_RULES = `## BinaryAnalysis 关键规则（压缩后恢复）

① 禁止作弊式验证 — 定位验证函数→能定位: 干净用Unicorn/复杂用Hook; 不能定位→CLI用subprocess/DLL用ctypes/GUI用gui_verify.py。详见 knowledge-base/verification-patterns.md
② 技术选型 — 计算密集型用 C/C++（见 knowledge-base/technology-selection.md）
③ ECDLP — 64-bit 以上必须用 C（见 knowledge-base/ecdlp-solving.md）
④ 环境检测 — detect_env.py 检测工具链，缓存 24h
⑤ 静态分析 15 分钟无进展 → 立即切动态分析
⑥ 超时监控 — idat 300s 超时，LLM 60s 无响应反思方案
⑦ 失败快速切换 — 同一方向连续 2 次失败 → 强制换方向
⑧ 不要执着 Python — 什么技术栈适合就用什么
⑨ 禁止使用 workdir 参数 — 所有中间文件写入 ~/bw-ida-pro-analysis/workspace/
⑩ 方案优先 — 未输出方案前禁止执行任何 idat 分析调用
⑪ 数据库锁定时立即报错退出
⑫ 分析结果必须区分事实和推测，标注置信度`;

const COMPACTION_CONTEXT_PROMPT = `## BinaryAnalysis 分析状态（压缩时必须保留）

当总结此会话时，如果包含 BinaryAnalysis 相关内容，你必须保留以下信息：

### 1. 分析目标
- 目标二进制文件路径
- 文件类型（exe/dll/so）和架构

### 2. 已完成的分析
- 已识别的关键函数及其地址和用途
- 已发现的分析结论（如 bug、特殊条件、算法特征）
- 已执行的 idat 查询和结果摘要

### 3. 当前状态
- 当前分析阶段（信息收集/分析规划/执行/验证）
- 待完成的分析步骤
- 失败记录（什么方向已尝试并失败，避免重复）

### 4. 验证状态
- 验证结果和置信度评估
- 是否有待验证的假设

### 5. 显式约束（原文保留）
- 用户明确提出的要求（如"不要修改数据库"、"先分析再绕过"）
- 置信度声明：区分"来自 IDA 数据库的事实"和"AI 推理（标注置信度）"

${COMPACT_RULES}`;

function readJsonSafe(filePath) {
  try {
    if (existsSync(filePath)) {
      return JSON.parse(readFileSync(filePath, "utf-8"));
    }
  } catch {}
  return null;
}

// --- sessionID → TASK_DIR 映射 ---

function getTaskDir(sessionID) {
  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    const data = readJsonSafe(filePath);
    return data?.task_dir || null;
  } catch {
    return null;
  }
}

function removeTaskSession(sessionID) {
  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    if (existsSync(filePath)) {
      unlinkSync(filePath);
    }
  } catch {
    // 静默降级：删除失败不影响主流程
  }
}

const sessionStates = new Map();

export const BinaryAnalysisPlugin = async ({ directory }) => {
  debugLog(`BinaryAnalysisPlugin loaded: directory=${directory}`);
  return {
    "experimental.session.compacting": async (input, output) => {
      debugLog(`compacting: sessionID=${input.sessionID}`);
      // 动态注入环境信息摘要（从 env_cache.json 和 config.json 实时读取）
      const config = readJsonSafe(CONFIG_FILE);
      const envData = readJsonSafe(ENV_CACHE_FILE);
      const envInfo = envData?.data;
      const scriptsDir = config?.scripts_dir || "";
      const idaPath = config?.ida_path || "";

      let envSummary = "## 环境信息（压缩时自动注入）\n";
      if (idaPath) {
        envSummary += `- IDA Pro: ${idaPath}\n`;
      }
      if (scriptsDir) {
        envSummary += `- 脚本目录 ($SCRIPTS_DIR): ${scriptsDir}\n`;
      }
      if (envInfo) {
        if (envInfo.venv_python) {
          envSummary += `- BA_PYTHON: ${envInfo.venv_python}\n`;
        }
        const compiler = envInfo.compiler;
        if (compiler?.available) {
          envSummary += `- 编译器: ${compiler.type} (${compiler.path})\n`;
        }
        if (envInfo.packages) {
          const pkgs = Object.entries(envInfo.packages)
            .filter(([, v]) => v.available)
            .map(([k, v]) => `${k}@${v.version}`)
            .join(", ");
          if (pkgs) envSummary += `- Python 包: ${pkgs}\n`;
        }
      }
      output.context.push(envSummary);
      output.context.push(COMPACTION_CONTEXT_PROMPT);

      // 精确恢复 TASK_DIR：用 sessionID 查映射文件
      const sid = input.sessionID;
      if (sid) {
        const taskDir = getTaskDir(sid);
        if (taskDir) {
          debugLog(`compacting: TASK_DIR recovered=${taskDir}`);
          output.context.push(`## TASK_DIR（不可省略 — 压缩后必须保留）
当前会话的任务目录: ${taskDir}
所有中间输出文件在此目录下。后续分析必须使用此路径作为 $TASK_DIR。
如果用户明确要求使用新的任务目录，重新执行"任务目录约定"中的创建命令即可切换。`);
        } else {
          debugLog(`compacting: TASK_DIR not found for sessionID=${sid}`);
        }
      }
    },

    "experimental.chat.system.transform": async (input, output) => {
      const config = readJsonSafe(CONFIG_FILE);
      if (!config) {
        debugLog("system.transform: config.json not found, skipping");
        return;
      }

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
        if (envInfo.venv_python) {
          envSection += `- BA_PYTHON: ${envInfo.venv_python}\n`;
        }
        if (envInfo.packages) {
          const pkgs = Object.entries(envInfo.packages)
            .filter(([, v]) => v.available)
            .map(([k, v]) => `${k}@${v.version}`)
            .join(", ");
          envSection += `- Python 包: ${pkgs}\n`;
        }
      }

      output.system.push(envSection);
    },

    "tool.execute.before": async (input, output) => {
      debugLog(`tool.execute.before: tool=${input.tool} sessionID=${input.sessionID}`);
      if (input.tool.toLowerCase() !== "bash") return;
      const cmd = output.args?.command;
      if (typeof cmd !== "string" || !cmd) return;
      const sid = input.sessionID;
      if (!sid) return;
      const isUnix = !!process.env.SHELL || !!process.env.MSYSTEM;
      const isPowerShell = !isUnix && !!process.env.PSModulePath;
      if (isUnix) {
        // bash 单引号转义：' → '\''（结束引号→转义单引号→重新开始引号）
        const safeSid = sid.replace(/'/g, "'\\''");
        output.args.command = `SESSION_ID='${safeSid}' ${cmd}`;
      } else if (isPowerShell) {
        // PowerShell 单引号转义：' → ''（两个单引号）
        const safeSid = sid.replace(/'/g, "''");
        output.args.command = `$env:SESSION_ID='${safeSid}'; ${cmd}`;
      } else {
        // cmd.exe 双引号内不需要转义单引号
        output.args.command = `set "SESSION_ID=${sid}" && ${cmd}`;
      }
      debugLog(`injected: ${output.args.command.slice(0, 120)}`);
    },

    event: async (input) => {
      const { event } = input;
      const props = event.properties || {};
      // session.created/deleted 的 properties 是 { info: Session }，sessionID 在 info.id
      // session.compacted 的 properties 是 { sessionID: string }
      const sessionID = props.info?.id ?? props.sessionID;

      if (event.type === "session.created") {
        if (sessionID) {
          debugLog(`event: session.created id=${sessionID}`);
          sessionStates.set(sessionID, { createdAt: Date.now() });
        }
      }

      if (event.type === "session.deleted") {
        if (sessionID) {
          debugLog(`event: session.deleted id=${sessionID}`);
          sessionStates.delete(sessionID);
          removeTaskSession(sessionID);
        }
      }

      if (event.type === "session.compacted") {
        debugLog(`event: session.compacted id=${sessionID}`);
      }
    },
  };
};
