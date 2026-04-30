import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";
import { fileURLToPath } from "url";
import type { Plugin } from "@opencode-ai/plugin";

const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url));
const OPENCODE_ROOT = dirname(PLUGIN_DIR);

const DATA_DIR = join(homedir(), "bw-security-analysis");
const CONFIG_FILE = join(DATA_DIR, "config.json");
const ENV_CACHE_FILE = join(DATA_DIR, "env_cache.json");
const WORKSPACE_DIR = join(DATA_DIR, "workspace");
const TASK_SESSIONS_DIR = join(WORKSPACE_DIR, ".task_sessions");
const DEBUG_LOG = join(DATA_DIR, "plugin_debug.log");
const MAX_LOG_SIZE = 5 * 1024 * 1024;
const KEEP_SIZE = 2 * 1024 * 1024;

function debugLog(msg: string): void {
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

interface ToolConfig {
  path: string;
  agents?: string[];
  required?: boolean;
  version_cmd?: string[];
  description?: string;
}

interface ConfigData {
  ida_path?: string;
  tools?: Record<string, ToolConfig>;
}

interface EnvData {
  data?: {
    venv_python?: string;
    compiler?: {
      available: boolean;
      type: string;
      path: string;
      vcvarsall?: string;
    };
    packages?: Record<string, { available: boolean; version: string }>;
    tools?: Record<string, { available: boolean; version: string | null }>;
  };
}

interface TaskSessionMapping {
  task_dir: string;
}

function readJsonSafe<T>(filePath: string): T | null {
  try {
    if (existsSync(filePath)) {
      return JSON.parse(readFileSync(filePath, "utf-8")) as T;
    }
  } catch {}
  return null;
}

function getTaskDir(sessionID: string): string | null {
  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    const data = readJsonSafe<TaskSessionMapping>(filePath);
    return data?.task_dir || null;
  } catch {
    return null;
  }
}

function removeTaskSession(sessionID: string): void {
  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    if (existsSync(filePath)) {
      unlinkSync(filePath);
    }
  } catch {
  }
}

function getToolsForAgent(agentName: string, config: ConfigData): Array<ToolConfig & { name: string }> {
  if (!config.tools) return [];
  return Object.entries(config.tools)
    .filter(([, tool]) => !tool.agents || tool.agents.includes(agentName))
    .map(([name, tool]) => ({ name, ...tool }));
}

function getScriptDir(agentName: string | undefined): string {
  const AGENT_SCRIPT_DIRS: Record<string, string> = {
    "binary-analysis": join(OPENCODE_ROOT, "binary-analysis"),
    "mobile-analysis": join(OPENCODE_ROOT, "mobile-analysis"),
  };
  return AGENT_SCRIPT_DIRS[agentName || ""] || AGENT_SCRIPT_DIRS["binary-analysis"];
}

function getCompactionReminder(agentName: string | undefined): string {
  if (agentName) {
    const promptPath = `.opencode/agents/${agentName}.md`;
    return `## 压缩恢复指令（压缩时必须保留）

上下文刚被压缩。继续分析前必须：
1. 重新读取 agent prompt（${promptPath}）获取完整规则
2. 恢复 $SCRIPTS_DIR、$IDA_SCRIPTS_DIR、$TASK_DIR 等关键变量（见 agent prompt 的"变量丢失自愈"章节）`;
  }
  return `## 压缩恢复指令（压缩时必须保留）

上下文刚被压缩。继续分析前必须：
1. 请告知当前使用的是哪个 Agent（如 binary-analysis、mobile-analysis）
2. 根据 Agent 名读取对应的 agent prompt（.opencode/agents/<agent-name>.md）
3. 恢复 $SCRIPTS_DIR、$IDA_SCRIPTS_DIR、$TASK_DIR 等关键变量`;
}

function getCompactionContext(agentName: string | undefined): string {
  let context = `## 分析状态（压缩时必须保留）

当总结此会话时，如果包含分析相关内容，你必须保留以下信息：

### 1. 分析目标
- 目标文件路径和类型
- 文件架构

### 2. 已完成的分析
- 已识别的关键函数/类及其地址/名称和用途
- 已发现的分析结论
- 当前分析阶段和待完成步骤
- 失败记录（已尝试方向，避免重复）
- 验证结果和置信度
- 用户显式约束`;

  if (agentName === "binary-analysis") {
    context += `

### IDA 分析状态
- IDA 数据库路径
- 已执行的 idat 查询和结果摘要`;
  }

  if (agentName === "mobile-analysis") {
    context += `

### 移动端分析状态
- 已解包路径
- 已识别的 native 库列表（.so / .dylib）
- 当前设备连接状态（device_id、frida_server 运行/端口）`;
  }

  return context;
}

function buildEnvSection(
  agentName: string | undefined,
  config: ConfigData,
  envInfo: EnvData["data"],
): string {
  const scriptsDir = getScriptDir(agentName);
  const idaScriptsDir = join(OPENCODE_ROOT, "binary-analysis");
  const idaPath = config.ida_path || "未配置";

  let envSection = `\n## 环境信息\n`;
  envSection += `- IDA Pro: ${idaPath}\n`;
  envSection += `- 脚本目录 ($SCRIPTS_DIR): ${scriptsDir}\n`;
  envSection += `- IDA 通用脚本目录 ($IDA_SCRIPTS_DIR): ${idaScriptsDir}\n`;

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

  // 注入外部工具（按 agent 过滤；agent 未知时不过滤，注入全部）
  if (config.tools) {
    const tools = agentName
      ? getToolsForAgent(agentName, config)
      : Object.entries(config.tools).map(([name, tool]) => ({ name, ...tool }));
    const envTools = envInfo?.tools || {};
    for (const tool of tools) {
      const toolStatus = envTools[tool.name];
      if (toolStatus?.available) {
        const ver = toolStatus.version || "可用";
        envSection += `- ${tool.description || tool.name}: ${tool.path} (${ver})\n`;
      }
    }
  }

  return envSection;
}

interface SessionState {
  createdAt: number;
}

const sessionStates = new Map<string, SessionState>();
const sessionAgentMap = new Map<string, string>();

export const SecurityAnalysisPlugin: Plugin = async ({ directory }) => {
  debugLog(`SecurityAnalysisPlugin loaded: directory=${directory}`);
  return {
    "chat.message": async (input) => {
      const agent = (input as { agent?: string })?.agent;
      const sessionID = (input as { sessionID?: string })?.sessionID;
      if (agent && sessionID) {
        sessionAgentMap.set(sessionID, agent);
        debugLog(`chat.message: sessionID=${sessionID} agent=${agent}`);
      }
    },

    "experimental.session.compacting": async (input, output) => {
      const sid = input?.sessionID;
      const agentName = sid ? sessionAgentMap.get(sid) : undefined;
      debugLog(`compacting: sessionID=${sid} agent=${agentName}`);
      const config = readJsonSafe<ConfigData>(CONFIG_FILE);
      const envData = readJsonSafe<EnvData>(ENV_CACHE_FILE);
      const envInfo = envData?.data;
      const idaPath = config?.ida_path || "";

      let envSummary = `## 环境信息（压缩时自动注入）\n`;
      if (idaPath) {
        envSummary += `- IDA Pro: ${idaPath}\n`;
      }
      const scriptsDir = getScriptDir(agentName);
      const idaScriptsDir = join(OPENCODE_ROOT, "binary-analysis");
      envSummary += `- 脚本目录 ($SCRIPTS_DIR): ${scriptsDir}\n`;
      envSummary += `- IDA 通用脚本目录 ($IDA_SCRIPTS_DIR): ${idaScriptsDir}\n`;
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
      output.context.push(getCompactionContext(agentName));
      output.context.push(getCompactionReminder(agentName));

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
      const config = readJsonSafe<ConfigData>(CONFIG_FILE);
      if (!config) {
        debugLog("system.transform: config.json not found, skipping");
        return;
      }

      const envData = readJsonSafe<EnvData>(ENV_CACHE_FILE);
      const envInfo = envData?.data;
      const sessionID = (input as { sessionID?: string })?.sessionID;
      const agentName = sessionID ? sessionAgentMap.get(sessionID) : undefined;

      debugLog(`system.transform: sessionID=${sessionID} agent=${agentName}`);

      const envSection = buildEnvSection(agentName, config, envInfo);
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
      const sessionID: string | undefined = props.info?.id ?? props.sessionID;

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
          sessionAgentMap.delete(sessionID);
          removeTaskSession(sessionID);
        }
      }

      if (event.type === "session.compacted") {
        debugLog(`event: session.compacted id=${sessionID}`);
      }
    },
  };
};
