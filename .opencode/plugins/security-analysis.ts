import {
  readFileSync,
  writeFileSync,
  existsSync,
  unlinkSync,
  mkdirSync,
  statSync,
} from "fs";
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
const LOGS_DIR = join(DATA_DIR, "logs");
const DEFAULT_LOG = join(LOGS_DIR, "plugin_debug.log");
const MAX_LOG_SIZE = 5 * 1024 * 1024;
const KEEP_SIZE = 2 * 1024 * 1024;

const PRIMARY_AGENTS = ["binary-analysis", "mobile-analysis"];

function getLogFilePath(primaryAgent: string | undefined): string {
  if (primaryAgent && PRIMARY_AGENTS.includes(primaryAgent)) {
    return join(LOGS_DIR, `${primaryAgent}.log`);
  }
  return DEFAULT_LOG;
}

function trimLogFile(logFile: string): void {
  try {
    if (existsSync(logFile) && statSync(logFile).size > MAX_LOG_SIZE) {
      const content = readFileSync(logFile, "utf-8");
      const keep = content.slice(-KEEP_SIZE);
      const firstNewline = keep.indexOf("\n");
      writeFileSync(
        logFile,
        firstNewline >= 0 ? keep.slice(firstNewline + 1) : keep,
      );
    }
  } catch {}
}

function writeLog(logFile: string, msg: string): void {
  try {
    mkdirSync(dirname(logFile), { recursive: true });
    trimLogFile(logFile);
    const ts = new Date().toLocaleString("zh-CN", { hour12: false });
    writeFileSync(logFile, `[${ts}] ${msg}\n`, { flag: "a" });
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

function readJsonSafe<T>(filePath: string, sessionID?: string): T | null {
  try {
    if (existsSync(filePath)) {
      return JSON.parse(readFileSync(filePath, "utf-8")) as T;
    }
  } catch (e) {
    debugLog(`readJsonSafe failed: ${filePath} error=${e}`, sessionID);
  }
  return null;
}

function getTaskDir(sessionID: string): string | null {
  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    const data = readJsonSafe<TaskSessionMapping>(filePath, sessionID);
    const result = data?.task_dir || null;
    debugLog(
      `getTaskDir: sessionID=${sessionID} file=${filePath} result=${result}`,
      sessionID,
    );
    return result;
  } catch {
    return null;
  }
}

function removeTaskSession(sessionID: string): void {
  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    if (existsSync(filePath)) {
      debugLog(`removeTaskSession: deleting ${filePath}`, sessionID);
      unlinkSync(filePath);
    }
  } catch (e) {
    debugLog(
      `removeTaskSession failed: sessionID=${sessionID} error=${e}`,
      sessionID,
    );
  }
}

function getToolsForAgent(
  agentName: string,
  config: ConfigData,
): Array<ToolConfig & { name: string }> {
  if (!config.tools) return [];
  return Object.entries(config.tools)
    .filter(([, tool]) => !tool.agents || tool.agents.includes(agentName))
    .map(([name, tool]) => ({ name, ...tool }));
}

// 根据实际 agent 名获取脚本目录；子 agent（如 "general"）不在映射表中时，
// 回退到 primaryAgent 对应的目录，最终回退到 binary-analysis
function getScriptDir(
  agentName: string | undefined,
  fallbackAgent?: string,
): string {
  const AGENT_SCRIPT_DIRS: Record<string, string> = {
    "binary-analysis": join(OPENCODE_ROOT, "binary-analysis"),
    "mobile-analysis": join(OPENCODE_ROOT, "mobile-analysis"),
  };
  return (
    AGENT_SCRIPT_DIRS[agentName || ""] ||
    AGENT_SCRIPT_DIRS[fallbackAgent || ""] ||
    AGENT_SCRIPT_DIRS["binary-analysis"]
  );
}

const AGENTS_DIR = join(OPENCODE_ROOT, "agents");

function getCompactionReminder(agentName: string | undefined): string {
  if (agentName) {
    const promptPath = join(AGENTS_DIR, `${agentName}.md`);
    return `## 压缩恢复指令（压缩时必须保留）

上下文刚被压缩。继续分析前必须：
1. 重新读取 agent prompt（${promptPath}）获取完整规则
2. 恢复 $SCRIPTS_DIR、$IDA_SCRIPTS_DIR、$TASK_DIR 等关键变量（见 agent prompt 的"变量丢失自愈"章节）`;
  }
  return `## 压缩恢复指令（压缩时必须保留）

上下文刚被压缩。继续分析前必须：
1. 请告知当前使用的是哪个 Agent（如 binary-analysis、mobile-analysis）
2. 根据 Agent 名读取 ${AGENTS_DIR}/<agent-name>.md
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
  sessionID?: string,
): string {
  const fallbackAgent = getPrimaryAgent(sessionID);
  const scriptsDir = getScriptDir(agentName, fallbackAgent);
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

// ─── session 管理 ──────────────────────────────────────────────────────
//
// 数据结构
// - createdAt:   session 初始化时间（ensureSession 设置）
// - agentName:   当前实际使用的 agent 名（chat.message 设置，如 "binary-analysis"）
// - primaryAgent: 所属主 agent 名（用于日志路由和工具目录回退）
//                主 session: chat.message 中根据 PRIMARY_AGENTS 设置
//                子 session: ensureSession 从父 session 继承
//
// 恢复策略
// 插件重启后内存 Map 清空，OpenCode 不会为已有 session 重发 session.created 事件。
// ensureSession 通过 client API 按需查询 session info（含 parentID），
// 递归解析父链恢复 primaryAgent。每个 session 在每个进程生命周期内最多触发
// 一次 API 调用，后续访问纯内存读取，零开销。
interface SessionData {
  createdAt: number;
  agentName?: string;
  primaryAgent?: string;
}

const sessions = new Map<string, SessionData>();

// OpenCode client，在 Plugin 函数中初始化
let opencodeClient: {
  session: {
    get: (options: {
      path: { id: string };
      query?: { directory?: string };
    }) => Promise<{
      data?: { id: string; parentID?: string; [k: string]: unknown };
      error?: unknown;
    }>;
  };
} | null = null;

// 并发去重：同一 sessionID 的并发 ensureSession 调用共享同一个 Promise
const pendingEnsures = new Map<string, Promise<SessionData | undefined>>();

function getPrimaryAgent(sessionID?: string): string | undefined {
  return sessionID ? sessions.get(sessionID)?.primaryAgent : undefined;
}

function debugLog(msg: string, sessionID?: string): void {
  const logFile = getLogFilePath(getPrimaryAgent(sessionID));
  writeLog(logFile, msg);
}

/**
 * 确保指定 session 的数据可用。
 * - 已在 Map 中 → 直接返回（零开销）
 * - 不在 Map 中 → 调用 OpenCode client API 查询 session info，
 *   递归解析父链继承 primaryAgent，写入 Map 后返回。
 * - 同一 session 的并发调用共享同一个 Promise，避免重复 API 请求。
 */
async function ensureSession(
  sessionID: string,
): Promise<SessionData | undefined> {
  const existing = sessions.get(sessionID);
  if (existing) return existing;

  const pending = pendingEnsures.get(sessionID);
  if (pending) return pending;

  const promise = doEnsureSession(sessionID);
  pendingEnsures.set(sessionID, promise);
  try {
    return await promise;
  } finally {
    pendingEnsures.delete(sessionID);
  }
}

async function doEnsureSession(
  sessionID: string,
): Promise<SessionData | undefined> {
  if (!opencodeClient) {
    debugLog(`ensureSession: client 未初始化, sessionID=${sessionID}`);
    return undefined;
  }

  try {
    const response = await opencodeClient.session.get({
      path: { id: sessionID },
    });
    if (response.error) {
      debugLog(
        `ensureSession: API 错误 sessionID=${sessionID} error=${JSON.stringify(response.error)}`,
      );
      return undefined;
    }
    const sessionInfo = response.data;
    if (!sessionInfo) {
      debugLog(`ensureSession: API 返回空数据 sessionID=${sessionID}`);
      return undefined;
    }

    // 递归解析父链
    let primaryAgent: string | undefined;
    if (sessionInfo.parentID) {
      const parent = await ensureSession(sessionInfo.parentID);
      primaryAgent = parent?.primaryAgent;
    }

    const session: SessionData = {
      createdAt: Date.now(),
      primaryAgent,
    };
    sessions.set(sessionID, session);
    debugLog(
      `ensureSession: 恢复 sessionID=${sessionID} primaryAgent=${primaryAgent || "无"} parentID=${sessionInfo.parentID || "无"}`,
      sessionID,
    );
    return session;
  } catch (e) {
    debugLog(`ensureSession: 异常 sessionID=${sessionID} error=${e}`);
    return undefined;
  }
}

/**
 * 统一的 hook 入口守卫：
 * 1. 确保 session 数据可用（必要时通过 API 恢复）
 * 2. 验证 primaryAgent 存在
 * 3. 任一条件不满足 → 记录日志并返回 undefined
 */
async function requireSessionWithPrimary(
  hookName: string,
  sessionID?: string,
): Promise<SessionData | undefined> {
  if (!sessionID) {
    debugLog(`${hookName}: 跳过 — 无 sessionID`);
    return undefined;
  }
  const session = await ensureSession(sessionID);
  if (!session) {
    debugLog(
      `${hookName}: 跳过 — sessionID=${sessionID} 无法初始化`,
      sessionID,
    );
    return undefined;
  }
  if (!session.primaryAgent) {
    debugLog(
      `${hookName}: 跳过 — sessionID=${sessionID} 无 primaryAgent（非 PRIMARY_AGENTS session）`,
      sessionID,
    );
    return undefined;
  }
  return session;
}

export const SecurityAnalysisPlugin: Plugin = async (input) => {
  const { client, directory } = input;
  opencodeClient = client;

  debugLog(`=== SecurityAnalysisPlugin loaded ===`);
  debugLog(`  PLUGIN_DIR: ${PLUGIN_DIR}`);
  debugLog(`  OPENCODE_ROOT: ${OPENCODE_ROOT}`);
  debugLog(`  DATA_DIR: ${DATA_DIR}`);
  debugLog(`  CONFIG_FILE: ${CONFIG_FILE}`);
  debugLog(`  ENV_CACHE_FILE: ${ENV_CACHE_FILE}`);
  debugLog(`  WORKSPACE_DIR: ${WORKSPACE_DIR}`);
  debugLog(`  TASK_SESSIONS_DIR: ${TASK_SESSIONS_DIR}`);
  debugLog(`  LOGS_DIR: ${LOGS_DIR}`);
  debugLog(`  DEFAULT_LOG: ${DEFAULT_LOG}`);
  debugLog(`  directory param: ${directory}`);
  debugLog(`  config exists: ${existsSync(CONFIG_FILE)}`);
  debugLog(`  env_cache exists: ${existsSync(ENV_CACHE_FILE)}`);
  debugLog(`  opencodeClient: ${!!opencodeClient}`);
  return {
    // 用户发送消息时触发（awaited，宿主等待完成）
    // 职责：记录 agentName + 设置主 session 的 primaryAgent
    // 注意：这是唯一能获取 input.agent 的 hook 点
    //       system.transform / tool.execute.before 没有 agent 信息
    "chat.message": async (input) => {
      const agent = (input as { agent?: string })?.agent;
      const sessionID = (input as { sessionID?: string })?.sessionID;
      if (!agent) {
        debugLog("chat.message: 跳过 — 无 agent", sessionID);
        return;
      }
      if (!sessionID) {
        debugLog(`chat.message: 跳过 — 无 sessionID, agent=${agent}`);
        return;
      }
      if (!PRIMARY_AGENTS.includes(agent)) {
        debugLog(
          `chat.message: 跳过 — agent=${agent} 不在 PRIMARY_AGENTS 中, sessionID=${sessionID}`,
          sessionID,
        );
        return;
      }

      // 确保 session 存在（重启后懒恢复）
      const session = await ensureSession(sessionID);
      if (!session) return;

      session.agentName = agent;
      session.primaryAgent = agent;
      debugLog(
        `chat.message: sessionID=${sessionID} agent=${agent} primaryAgent=${agent}`,
        sessionID,
      );
    },

    // 上下文压缩前触发（awaited）
    // 职责：注入环境摘要 + 分析状态保留提示 + TASK_DIR，防止压缩丢失关键信息
    "experimental.session.compacting": async (input, output) => {
      const sid = input?.sessionID;
      const session = await requireSessionWithPrimary("compacting", sid);
      if (!session) return;
      const agentName = session.agentName;
      debugLog(
        `compacting: sessionID=${sid} agent=${agentName} primaryAgent=${session.primaryAgent}`,
        sid,
      );
      const config = readJsonSafe<ConfigData>(CONFIG_FILE, sid);
      const envData = readJsonSafe<EnvData>(ENV_CACHE_FILE, sid);
      const envInfo = envData?.data;

      const envSection = buildEnvSection(agentName, config || {}, envInfo, sid);
      const envSummary = envSection.replace(
        "\n## 环境信息\n",
        "## 环境信息（压缩时自动注入）\n",
      );
      output.context.push(envSummary);
      const compactionCtx = getCompactionContext(agentName);
      const compactionReminder = getCompactionReminder(agentName);
      output.context.push(compactionCtx);
      output.context.push(compactionReminder);

      debugLog(`=== compacting 注入内容开始 ===`, sid);
      debugLog(`sid:${sid}\n`, sid);
      debugLog(`agent:${agentName}\n`, sid);
      debugLog(`envSummary:\n${envSummary}\n`, sid);
      debugLog(`compactionCtx:\n${compactionCtx}\n`, sid);
      debugLog(`compactionReminder:\n${compactionReminder}`, sid);
      debugLog(`=== compacting 注入内容结束 ===`, sid);

      if (sid) {
        const taskDir = getTaskDir(sid);
        if (taskDir) {
          debugLog(`compacting: TASK_DIR recovered=${taskDir}`, sid);
          output.context.push(`## TASK_DIR（不可省略 — 压缩后必须保留）
当前会话的任务目录: ${taskDir}
所有中间输出文件在此目录下。后续分析必须使用此路径作为 $TASK_DIR。
如果用户明确要求使用新的任务目录，重新执行"任务目录约定"中的创建命令即可切换。`);
        } else {
          debugLog(`compacting: TASK_DIR not found for sessionID=${sid}`, sid);
        }
      }
    },

    // 每次 LLM 请求前触发（awaited）
    // 职责：按 agent 注入环境信息到系统提示
    // 注意：output.system 每次请求都重建（const system: string[] = []），
    //       所以必须每次都 push，不会累积
    "experimental.chat.system.transform": async (input, output) => {
      const sessionID = (input as { sessionID?: string })?.sessionID;
      const session = await requireSessionWithPrimary(
        "system.transform",
        sessionID,
      );
      if (!session) return;

      const config = readJsonSafe<ConfigData>(CONFIG_FILE, sessionID);
      if (!config) {
        debugLog(
          "system.transform: config.json not found, skipping",
          sessionID,
        );
        return;
      }

      const envData = readJsonSafe<EnvData>(ENV_CACHE_FILE, sessionID);
      const envInfo = envData?.data;
      const agentName = session.agentName;

      const envSection = buildEnvSection(agentName, config, envInfo, sessionID);
      output.system.push(envSection);
      debugLog(
        `system.transform: sessionID=${sessionID} agent=${agentName} primaryAgent=${session.primaryAgent} length=${envSection.length}, envSection=\n${envSection}`,
        sessionID,
      );
    },

    // 工具执行前触发（awaited）
    // 职责：为 bash 命令注入 SESSION_ID 环境变量
    "tool.execute.before": async (input, output) => {
      const sid = input.sessionID;
      const session = await requireSessionWithPrimary(
        "tool.execute.before",
        sid,
      );
      if (!session) return;
      debugLog(`tool.execute.before: tool=${input.tool} sessionID=${sid}`, sid);

      if (input.tool.toLowerCase() !== "bash") return;
      const cmd = output.args?.command;
      if (typeof cmd !== "string" || !cmd) return;
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
      debugLog(`injected: ${output.args.command.slice(0, 120)}`, sid);
    },

    // session 生命周期事件（fire-and-forget，宿主不等待完成）
    // 职责：清理 session 数据 + 记录生命周期日志
    // 注意：session.created 不再做 session 初始化（由 ensureSession 按需完成），
    //       但仍记录日志以保持可观测性
    event: async (input) => {
      const { event } = input;
      const props = event.properties || {};
      const sessionID: string | undefined = props.info?.id ?? props.sessionID;

      if (event.type === "session.created") {
        const parentID = (props?.info as { parentID?: string } | undefined)
          ?.parentID;
        debugLog(
          `event: session.created id=${sessionID} parentID=${parentID || "无"}`,
          sessionID,
        );
      }

      // 删除 session：统一清理所有状态 + task session 文件
      if (event.type === "session.deleted") {
        if (sessionID) {
          debugLog(`event: session.deleted id=${sessionID}`, sessionID);
          sessions.delete(sessionID);
          removeTaskSession(sessionID);
        }
      }

      // 压缩完成：仅记录日志（状态恢复由 compacting hook 在压缩前注入）
      if (event.type === "session.compacted") {
        debugLog(`event: session.compacted id=${sessionID}`, sessionID);
      }
    },
  };
};
