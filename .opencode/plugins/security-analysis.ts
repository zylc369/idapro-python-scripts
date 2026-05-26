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
import { tool } from "@opencode-ai/plugin";

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

const AGENT_BINARY_ANALYSIS = "binary-analysis";
const AGENT_MOBILE_ANALYSIS = "mobile-analysis";
const AGENT_WEB_ANALYSIS = "web-analysis";
const AGENT_SECURITY_ANALYSIS_EVOLVE = "security-analysis-evolve";
const AGENT_SECURITY_COORDINATOR = "security-coordinator";

const PRIMARY_AGENTS = [
  AGENT_BINARY_ANALYSIS,
  AGENT_MOBILE_ANALYSIS,
  AGENT_WEB_ANALYSIS,
  AGENT_SECURITY_ANALYSIS_EVOLVE,
  AGENT_SECURITY_COORDINATOR,
];

const AGENT_SCRIPT_DIRS: Record<string, string> = {};
for (const name of PRIMARY_AGENTS) {
  AGENT_SCRIPT_DIRS[name] = join(OPENCODE_ROOT, name);
}

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

// getTaskDir 内存缓存（避免每次 debugLog 都读文件系统）
const taskDirCache = new Map<string, string | null>();

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
  // 先查缓存
  const cached = taskDirCache.get(sessionID);
  if (cached !== undefined) return cached;

  try {
    const filePath = join(TASK_SESSIONS_DIR, `${sessionID}.json`);
    const data = readJsonSafe<TaskSessionMapping>(filePath);
    const result = data?.task_dir || null;
    taskDirCache.set(sessionID, result);
    return result;
  } catch {
    taskDirCache.set(sessionID, null);
    return null;
  }
}

function removeTaskSession(sessionID: string): void {
  taskDirCache.delete(sessionID);
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
// 回退到 primaryAgent 对应的目录；均无映射则返回 undefined
function getScriptDir(
  agentName: string | undefined,
  fallbackAgent?: string,
): string | undefined {
  return (
    AGENT_SCRIPT_DIRS[agentName || ""] ||
    AGENT_SCRIPT_DIRS[fallbackAgent || ""] ||
    undefined
  );
}

const AGENTS_DIR = join(OPENCODE_ROOT, "agents");
const AGENTS_RULES_DIR = join(OPENCODE_ROOT, "agents-rules");

// ─── 占位符展开 ──────────────────────────────────────────────────────
//
// Agent .md 文件中可以用 {{buwai-rule:片段名}} 引用 agents-rules/ 下的通用片段。
// Plugin 在 system.transform hook 中展开占位符，LLM 收到的是完整 prompt。
//
// 缓存策略：mtime 检测（statSync + mtimeMs 对比），文件改动后下次调用即生效。
// 依赖顺序：session 检查 → 占位符展开（每次）→ shouldInject（每 10 次环境注入）

interface SnippetCacheEntry { content: string | null; mtime: number; }
const snippetCache = new Map<string, SnippetCacheEntry>();

interface FrontmatterCacheEntry { result: boolean; mtime: number; }
const frontmatterCache = new Map<string, FrontmatterCacheEntry>();

// 解析 YAML frontmatter（仅扁平 key-value，不处理嵌套结构）
// 示例输入：---\nmode: primary\nbuwai-extension-id: binary-analysis\n---\n
// 返回：{ mode: "primary", "buwai-extension-id": "binary-analysis" }
function parseFrontmatter(content: string): Record<string, string> {
  // 匹配 --- 开头和结尾之间的内容（兼容 \r\n 和 \n）
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  if (!match) return {};
  const result: Record<string, string> = {};
  for (const line of match[1].split(/\r?\n/)) {
    // 只匹配顶层 key: value（缩进行如 "  external_directory:" 被跳过）
    const kv = line.match(/^([a-zA-Z0-9_-]+):\s*(.*)$/);
    if (kv) result[kv[1]] = kv[2].trim();
  }
  return result;
}

// 检查 agent .md 是否声明了 buwai-extension-id（有此字段才做占位符展开）
// 结果按 agentFile 路径缓存，mtime 变了才重新读取
function hasBuwaiExtensionId(agentFile: string): boolean {
  try {
    const stat = statSync(agentFile);
    const cached = frontmatterCache.get(agentFile);
    if (cached && cached.mtime === stat.mtimeMs) return cached.result;
    const content = readFileSync(agentFile, "utf-8");
    const fm = parseFrontmatter(content);
    const result = "buwai-extension-id" in fm;
    frontmatterCache.set(agentFile, { result, mtime: stat.mtimeMs });
    return result;
  } catch {
    return false;
  }
}

// 加载 agents-rules/<name>.md 片段文件，带 mtime 缓存
// 返回 null 表示文件不存在（调用方保留占位符原文）
function loadSnippet(name: string): string | null {
  const filePath = join(AGENTS_RULES_DIR, `${name}.md`);
  try {
    const stat = statSync(filePath);
    const cached = snippetCache.get(name);
    if (cached && cached.mtime === stat.mtimeMs) return cached.content;
    const content = readFileSync(filePath, "utf-8").trim();
    snippetCache.set(name, { content, mtime: stat.mtimeMs });
    return content;
  } catch {
    debugLog(`Snippet not found: ${filePath}`);
    return null;
  }
}

function getCompactionReminder(agentName: string | undefined): string {
  if (agentName) {
    const promptPath = join(AGENTS_DIR, `${agentName}.md`);
    const scriptsDir = getScriptDir(agentName);
    const restoreVars = scriptsDir
      ? `$OPENCODE_ROOT、$AGENT_DIR、$SHARED_DIR、$TASK_DIR`
      : `$OPENCODE_ROOT、$TASK_DIR`;
    return `## 压缩恢复指令（压缩时必须保留）

上下文刚被压缩。继续分析前必须：
1. 重新读取 agent prompt（${promptPath}）获取完整规则
2. 恢复 ${restoreVars} 等关键变量（见 agent prompt 的"变量丢失自愈"章节）`;
  }
  return `## 压缩恢复指令（压缩时必须保留）

上下文刚被压缩。继续分析前必须：
1. 请告知当前使用的是哪个 Agent（如 ${AGENT_BINARY_ANALYSIS}、${AGENT_MOBILE_ANALYSIS}、${AGENT_WEB_ANALYSIS}）
2. 根据 Agent 名读取 ${AGENTS_DIR}/<agent-name>.md
3. 恢复 $OPENCODE_ROOT、$AGENT_DIR、$SHARED_DIR、$TASK_DIR 等关键变量`;
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

  if (agentName === AGENT_BINARY_ANALYSIS) {
    context += `

### IDA 分析状态
- IDA 数据库路径
- 已执行的 idat 查询和结果摘要`;
  }

  if (agentName === AGENT_MOBILE_ANALYSIS) {
    context += `

### 移动端分析状态
- 已解包路径
- 已识别的 native 库列表（.so / .dylib）
- 当前设备连接状态（device_id、frida_server 运行/端口）`;
  }

  if (agentName === AGENT_WEB_ANALYSIS) {
    context += `

### Web 分析状态
- 目标 URL 和/或源码目录路径
- 已识别的技术栈和框架版本
- 已发现的攻击面和攻击链进度
- 已测试的攻击方向和结果`;
  }

  if (agentName === AGENT_SECURITY_COORDINATOR) {
    context += `

### Coordinator 编排状态
- 父任务目录路径
- 已完成的子任务列表（Agent 名、关键发现摘要）
- 待执行的子任务列表（Agent 名、任务描述）
- 当前执行阶段（分析/分发/聚合）`;
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

  let envSection = `\n## 环境信息\n`;
  envSection += `- 配置根目录 ($OPENCODE_ROOT): ${OPENCODE_ROOT}\n`;

  if (scriptsDir) {
    envSection += `- Agent 目录 ($AGENT_DIR): ${scriptsDir}\n`;
  }

  const idaScriptsDir = join(OPENCODE_ROOT, AGENT_BINARY_ANALYSIS);
  envSection += `- 共享目录 ($SHARED_DIR): ${idaScriptsDir}\n`;
  const idaPath = config.ida_path || "未配置";
  envSection += `- IDA Pro: ${idaPath}\n`;

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

// ─── 子会话 system 注入 ──────────────────────────────────────────────
//
// delegate_analysis 工具为子会话构建完整的 system 内容:
// 1. 子会话模式指令（跳过任务目录创建、结果格式要求）
// 2. 目标 Agent 的环境信息（复用 buildEnvSection 逻辑）

const VALID_SUB_AGENTS = [
  AGENT_BINARY_ANALYSIS,
  AGENT_MOBILE_ANALYSIS,
  AGENT_WEB_ANALYSIS,
];

function buildSubSessionSystem(
  targetAgent: string,
  subTaskDir: string,
  parentTaskDir: string,
): string {
  const config = readJsonSafe<ConfigData>(CONFIG_FILE);
  const envData = readJsonSafe<EnvData>(ENV_CACHE_FILE);
  const envInfo = envData?.data;

  // 复用 buildEnvSection 构建环境信息（会根据 agent 注入正确的 $AGENT_DIR 等）
  const envSection = buildEnvSection(targetAgent, config || {}, envInfo);

  return `## 子会话运行模式

你正在以子 Agent 模式运行，由 security-coordinator 编排。

### 关键约束

1. **任务目录**: $TASK_DIR = ${subTaskDir}
   - 此目录已存在，不需要创建
   - 所有中间文件、临时脚本、输出、报告写入此目录
2. **跳过阶段 0 的"创建任务目录"步骤**: 不要调用 create_task_dir.py
   - 环境检测仍需执行: \`python3 "$SHARED_DIR/scripts/detect_env.py" --output "$TASK_DIR/env.json"\`
   - $BA_PYTHON 初始化仍需执行（从 env.json 提取）
3. **结果格式要求**:
   - 详细分析报告写入 $TASK_DIR/report.md
   - 你返回的文本必须是结构化摘要，格式如下:

\`\`\`
## 分析摘要
（一句话说明分析结论）

## 关键发现
- 发现 1: ...
- 发现 2: ...

## 报告路径
- 详细报告: $TASK_DIR/report.md
- 中间数据: $TASK_DIR/

## 执行统计
- 耗时: Xm Xs
- 工具调用: X 次
\`\`\`

${envSection}`;
}

// ─── delegate_analysis 轮询常量与辅助函数 ────────────────────────────
//
// 基于 oh-my-openagent 的 promptAsync + poll 模式
// 参考: vendor/oh-my-openagent/src/tools/delegate-task/

const POLL_INTERVAL_MS = 2000;
const DEFAULT_POLL_TIMEOUT_MS = 30 * 60 * 1000; // 30 分钟

interface SessionMessage {
  info: { role: string; finish?: string; id: string; time?: { created: number } };
  parts?: Array<{ type: string; text?: string }>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * 判断子会话是否已完成（不再有 LLM 调用或工具执行）
 * 逻辑参考 oh-my-openagent sync-session-poller.ts isSessionComplete
 */
function isSessionComplete(messages: SessionMessage[]): boolean {
  let lastUser: SessionMessage | undefined;
  let lastAssistant: SessionMessage | undefined;

  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (!lastAssistant && msg.info?.role === "assistant") lastAssistant = msg;
    if (!lastUser && msg.info?.role === "user") lastUser = msg;
    if (lastUser && lastAssistant) break;
  }

  // 没有 assistant 回复 → 未完成
  if (!lastAssistant?.info?.finish) return false;
  // finish 为 "tool-calls" → 还有工具在执行
  if (["tool-calls", "unknown"].includes(lastAssistant.info.finish)) return false;
  // 还有 pending 的 tool parts
  const hasToolParts = lastAssistant.parts?.some(
    (p) => p.type === "tool" || p.type === "tool_use" || p.type === "tool-call",
  );
  if (hasToolParts) return false;
  // user 和 assistant 都必须有 id
  if (!lastUser?.info?.id || !lastAssistant?.info?.id) return false;
  // assistant 必须在 user 之后
  return lastUser.info.id < lastAssistant.info.id;
}

/**
 * 轮询子会话状态直到完成或超时
 * @returns null 表示正常完成，string 表示错误信息
 */
async function pollSubSession(
  parentSessionID: string,
  subSessionID: string,
  timeoutMs: number = DEFAULT_POLL_TIMEOUT_MS,
): Promise<string | null> {
  if (!opencodeClient) return "错误: OpenCode client 未初始化";

  const startTime = Date.now();
  let pollCount = 0;

  while (Date.now() - startTime < timeoutMs) {
    // 检查父会话是否还在运行（如果父会话已结束，应终止子会话）
    // 通过检查 sessions Map 判断父会话是否仍活跃
    const parentSession = sessions.get(parentSessionID);
    if (!parentSession) {
      debugLog(`delegate_analysis: 父会话已不在 sessions Map，终止轮询`, parentSessionID);
      await abortSubSession(subSessionID, "parent_session_gone");
      return "错误: 父会话已终止，子任务被取消";
    }

    await sleep(POLL_INTERVAL_MS);
    pollCount++;

    // 查询子会话状态
    let statusResult: { data?: Record<string, { type: string }> };
    try {
      statusResult = await opencodeClient.session.status();
    } catch (e) {
      debugLog(`delegate_analysis: 查询状态失败，重试 subSession=${subSessionID}`, parentSessionID);
      continue;
    }

    const allStatuses = statusResult.data ?? {};
    const sessionStatus = allStatuses[subSessionID];

    // 每 10 次轮询记录一次日志（避免日志膨胀）
    if (pollCount % 10 === 0) {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      debugLog(
        `delegate_analysis: 轮询中 pollCount=${pollCount} elapsed=${elapsed}s status=${sessionStatus?.type ?? "not_found"}`,
        parentSessionID,
      );
    }

    // 状态不是 idle → 继续等待
    if (sessionStatus && sessionStatus.type !== "idle") {
      continue;
    }

    // 状态为 idle 或不在 status 中，检查消息确认是否完成
    let messages: SessionMessage[];
    try {
      const messagesResult = await opencodeClient.session.messages({
        path: { id: subSessionID },
      });
      const rawData = messagesResult.data;
      messages = Array.isArray(rawData) ? rawData : [];
    } catch (e) {
      debugLog(`delegate_analysis: 获取消息失败，重试 subSession=${subSessionID}`, parentSessionID);
      continue;
    }

    if (isSessionComplete(messages)) {
      debugLog(`delegate_analysis: 子会话完成 subSession=${subSessionID} pollCount=${pollCount}`, parentSessionID);
      return null; // 正常完成
    }
  }

  // 超时
  debugLog(`delegate_analysis: 轮询超时 subSession=${subSessionID} timeout=${timeoutMs}ms`, parentSessionID);
  await abortSubSession(subSessionID, "poll_timeout");
  return `错误: 子 Agent 执行超时（${Math.floor(timeoutMs / 60000)} 分钟），已终止。\n子会话 ID: ${subSessionID}`;
}

/**
 * 中止子会话
 */
async function abortSubSession(subSessionID: string, reason: string): Promise<void> {
  if (!opencodeClient) return;
  debugLog(`delegate_analysis: 中止子会话 subSession=${subSessionID} reason=${reason}`);
  try {
    await opencodeClient.session.abort({ path: { id: subSessionID } });
  } catch (e) {
    debugLog(`delegate_analysis: 中止子会话失败 subSession=${subSessionID} error=${e}`);
  }
}

/**
 * 从子会话消息中提取最后一个 assistant 的文本输出
 */
async function fetchSubSessionResult(subSessionID: string, subTaskDir: string): Promise<string> {
  if (!opencodeClient) return "错误: OpenCode client 未初始化";

  try {
    const messagesResult = await opencodeClient.session.messages({
      path: { id: subSessionID },
    });
    const messages = Array.isArray(messagesResult.data) ? messagesResult.data as SessionMessage[] : [];

    // 按 time.created 降序排列 assistant 消息，找到有 text content 的
    const assistantMessages = messages
      .filter((m) => m.info?.role === "assistant")
      .sort((a, b) => (b.info?.time?.created ?? 0) - (a.info?.time?.created ?? 0));

    for (const msg of assistantMessages) {
      const textParts = msg.parts?.filter((p) => p.type === "text" && p.text) ?? [];
      const content = textParts.map((p) => p.text!).join("\n");
      if (content.trim()) return content;
    }

    return `子 Agent 已完成执行，但未返回文本结果。\n详细报告: ${subTaskDir}/report.md`;
  } catch (e) {
    return `错误: 读取子会话结果失败 - ${e}`;
  }
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
  systemTransformCount: number;
}

const sessions = new Map<string, SessionData>();
// 缓存已确认非 PRIMARY_AGENT 的 session，避免反复调 session.get API
const nonPrimarySessions = new Set<string>();

// OpenCode client，在 Plugin 函数中初始化
// 类型声明只列出实际使用的方法；运行时 client 是完整 SDK，包含所有 session API
let opencodeClient: {
  session: {
    get: (options: {
      path: { id: string };
      query?: { directory?: string };
    }) => Promise<{
      data?: { id: string; parentID?: string; [k: string]: unknown };
      error?: unknown;
    }>;
    create: (options: {
      body?: {
        parentID?: string;
        title?: string;
        permission?: Array<{ permission: string; action: string; pattern: string }>;
      };
      query?: { directory?: string };
    }) => Promise<{
      data?: { id: string; [k: string]: unknown };
      error?: unknown;
    }>;
    prompt: (options: {
      path: { id: string };
      body: {
        agent?: string;
        system?: string;
        parts: Array<{ type: string; text?: string }>;
      };
    }) => Promise<{
      data?: { parts?: Array<{ type: string; text?: string }> };
      error?: unknown;
    }>;
    promptAsync: (options: {
      path: { id: string };
      body: {
        agent?: string;
        system?: string;
        parts: Array<{ type: string; text?: string }>;
      };
    }) => Promise<{
      data?: unknown;
      error?: unknown;
    }>;
    status: () => Promise<{
      data?: Record<string, { type: string }>;
      error?: unknown;
    }>;
    messages: (options: {
      path: { id: string };
    }) => Promise<{
      data?: Array<{
        info: { role: string; finish?: string; id: string; time?: { created: number } };
        parts?: Array<{ type: string; text?: string }>;
      }>;
      error?: unknown;
    }>;
    abort: (options: {
      path: { id: string };
    }) => Promise<{
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
  // 优先写到任务目录下的 logs/plugin.log，没有任务目录则走集中日志
  const taskDir = sessionID ? getTaskDir(sessionID) : null;
  if (taskDir) {
    writeLog(join(taskDir, "logs", "plugin.log"), msg);
  } else {
    const logFile = getLogFilePath(getPrimaryAgent(sessionID));
    writeLog(logFile, msg);
  }
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
    debugLog(`doEnsureSession: client 未初始化, sessionID=${sessionID}`);
    return undefined;
  }

  try {
    const response = await opencodeClient.session.get({
      path: { id: sessionID },
    });

    debugLog(
      `doEnsureSession: client 响应 response=${JSON.stringify(response)}`,
      sessionID,
    );

    if (response.error) {
      debugLog(
        `doEnsureSession: API 错误 sessionID=${sessionID} error=${JSON.stringify(response.error)}`,
      );
      return undefined;
    }
    const sessionInfo = response.data;
    if (!sessionInfo) {
      debugLog(`doEnsureSession: API 返回空数据 sessionID=${sessionID}`);
      return undefined;
    }

    // 从 API 响应直接提取 agent（如果有的话）
    const directAgent = (sessionInfo as { agent?: string })?.agent;

    // 递归解析父链
    let primaryAgent: string | undefined;
    if (sessionInfo.parentID) {
      const parent = await ensureSession(sessionInfo.parentID);
      primaryAgent = parent?.primaryAgent;
    }
    // 优先使用直接 agent，回退到父链继承
    const agentName = directAgent || primaryAgent;

    const session: SessionData = {
      createdAt: Date.now(),
      agentName,
      primaryAgent: agentName,
      systemTransformCount: 0,
    };
    sessions.set(sessionID, session);
    debugLog(
      `doEnsureSession: 恢复 sessionID=${sessionID} agentName=${agentName || "无"} primaryAgent=${agentName || "无"} directAgent=${directAgent || "无"} parentID=${sessionInfo.parentID || "无"}`,
      sessionID,
    );
    return session;
  } catch (e) {
    debugLog(`doEnsureSession: 异常 sessionID=${sessionID} error=${e}`, sessionID);
    return undefined;
  }
}

/**
 * 统一的 hook 入口守卫：
 * 1. 优先从 Map 中查找 session（chat.message 已注册）
 * 2. Map miss 时，通过 session.get API 查询当前 session 的 agent
 *    - 如果是 PRIMARY_AGENT，恢复到 Map 中并返回
 *    - 否则跳过
 *
 * 修复：agent 中途切换后 chat.message 可能不重新触发，
 * 导致 Map 中无数据但实际 agent 已变为 PRIMARY_AGENT。
 */
async function requireSessionWithPrimary(
  hookName: string,
  sessionID?: string,
): Promise<SessionData | undefined> {
  if (!sessionID) {
    debugLog(`${hookName}: 跳过 — 无 sessionID`);
    return undefined;
  }

  const existing = sessions.get(sessionID);
  if (existing) return existing;

  // 已确认非 PRIMARY_AGENT，跳过（避免重复 API 调用）
  if (nonPrimarySessions.has(sessionID)) {
    debugLog(
      `${hookName}: 跳过 — 已缓存为非 PRIMARY sessionID=${sessionID}`,
      sessionID,
    );
    return undefined;
  }

  // Map miss — 尝试从 API 恢复（覆盖 agent 切换场景）
  if (!opencodeClient) {
    debugLog(`${hookName}: Map miss → opencodeClient 未初始化，无法恢复`);
    return undefined;
  }
  try {
    const response = await opencodeClient.session.get({
      path: { id: sessionID },
    });
    const sessionInfo = response?.data;
    const agentName = (sessionInfo as { agent?: string } | undefined)?.agent;

    if (agentName && PRIMARY_AGENTS.includes(agentName)) {
      debugLog(
        `${hookName}: Map miss → API 恢复成功 sessionID=${sessionID} agent=${agentName}`,
        sessionID,
      );
      const session: SessionData = {
        createdAt: Date.now(),
        agentName,
        primaryAgent: agentName,
        systemTransformCount: 0,
      };
      sessions.set(sessionID, session);
      return session;
    }

    // 缓存为非 PRIMARY，后续直接跳过
    nonPrimarySessions.add(sessionID);
    debugLog(
      `${hookName}: Map miss → API 返回非 PRIMARY agent=${agentName || "无"} sessionID=${sessionID}`,
      sessionID,
    );
  } catch (e) {
    debugLog(
      `${hookName}: Map miss → API 查询异常 sessionID=${sessionID} error=${e}`,
      sessionID,
    );
  }

  return undefined;
}

// ─── 时间线日志 ──────────────────────────────────────────────────────
//
// 记录工具执行和 session 事件的时间线，供事后复盘分析。
// 内存 buffer → 文件 flush 策略，避免每次事件都写磁盘。

type TimelineEventType = "tool.before" | "tool.after" | "session.status" | "session.error" | "heartbeat";

interface TimelineEvent {
  timestamp: number;
  type: TimelineEventType;
  tool?: string;
  detail?: string;
  duration?: number;
}

const MAX_TIMELINE_BUFFER = 500;
const timelineBuffers = new Map<string, TimelineEvent[]>();

// 工具开始执行时间戳（tool.execute.before → tool.execute.after 配对计算耗时）
const toolStartTimes = new Map<string, number>();

function formatTimelineEntry(event: TimelineEvent): string {
  const date = new Date(event.timestamp);
  const ts = date.toLocaleString("zh-CN", { hour12: false });
  const obj: Record<string, unknown> = {
    ts: event.timestamp,
    type: event.type,
  };
  if (event.tool) obj.tool = event.tool;
  if (event.detail) obj.detail = event.detail;
  if (event.duration !== undefined) obj.duration = event.duration;
  return `[${ts}] ${JSON.stringify(obj)}`;
}

function flushTimeline(sessionID: string): void {
  const buffer = timelineBuffers.get(sessionID);
  if (!buffer || buffer.length === 0) return;

  const taskDir = getTaskDir(sessionID);
  const logFile = taskDir
    ? join(taskDir, "logs", "timeline.log")
    : join(LOGS_DIR, `timeline-${sessionID}.log`);

  try {
    const lines = buffer.map(formatTimelineEntry).join("\n") + "\n";
    mkdirSync(dirname(logFile), { recursive: true });
    writeFileSync(logFile, lines, { flag: "a" });
  } catch (e) {
    debugLog(`flushTimeline failed: ${e}`, sessionID);
  }

  buffer.length = 0;
}

function recordTimeline(
  sessionID: string,
  event: TimelineEvent,
  flush = false,
): void {
  let buffer = timelineBuffers.get(sessionID);
  if (!buffer) {
    buffer = [];
    timelineBuffers.set(sessionID, buffer);
  }
  buffer.push(event);

  // buffer 满时自动 flush
  if (buffer.length >= MAX_TIMELINE_BUFFER || flush) {
    flushTimeline(sessionID);
  }
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

  // 写心跳文件，供 agent 检测 Plugin 是否正常加载
  const heartbeatFile = join(DATA_DIR, ".plugin-heartbeat");
  try {
    const heartbeat = {
      pid: process.pid,
      loadedAt: new Date().toISOString(),
      version: "1.0.0",
    };
    writeFileSync(heartbeatFile, JSON.stringify(heartbeat, null, 2));
    debugLog(`  心跳文件已写入: ${heartbeatFile}`);
  } catch (e) {
    debugLog(`  心跳文件写入失败: ${e}`);
  }

  return {
    // ─── 自定义工具 ──────────────────────────────────────────────────
    //
    // delegate_analysis: Coordinator 用此工具分发任务到专业 Agent
    // 创建子会话 → promptAsync 异步发送 → 轮询状态 → 返回摘要
    tool: {
      delegate_analysis: tool({
        description: `将分析任务分发到专业安全分析 Agent。

可用的 Agent:
- binary-analysis: IDA Pro 二进制逆向分析（.exe/.dll/.so）
- mobile-analysis: 移动应用分析（APK/IPA）
- web-analysis: Web 安全分析（URL/源码）

执行流程:
1. 创建子会话，指定目标 Agent
2. Agent 在父任务目录的子目录中工作
3. Agent 完成后返回结构化摘要
4. 详细报告写入磁盘: parent_task_dir/subdir_name/report.md`,

        args: {
          target_agent: tool.schema.string().describe("目标 Agent: binary-analysis, mobile-analysis, web-analysis"),
          task_prompt: tool.schema.string().describe("详细的任务描述，包含子 Agent 需要的所有上下文"),
          parent_task_dir: tool.schema.string().describe("父任务目录路径"),
          subdir_name: tool.schema.string().describe("子目录名称（在父任务目录下，如 binary-analysis）"),
          description: tool.schema.string().optional().describe("简短任务描述（3-5 字）"),
        },

        async execute(args, context) {
          const { target_agent, task_prompt, parent_task_dir, subdir_name, description } = args;

          // 1. 参数校验
          if (!VALID_SUB_AGENTS.includes(target_agent)) {
            return `错误: 无效的 Agent "${target_agent}"。可用: ${VALID_SUB_AGENTS.join(", ")}`;
          }

          if (!parent_task_dir || !subdir_name) {
            return `错误: parent_task_dir 和 subdir_name 不能为空`;
          }

          // 2. 创建子目录
          const subTaskDir = join(parent_task_dir, subdir_name);
          try {
            mkdirSync(subTaskDir, { recursive: true });
          } catch (e) {
            return `错误: 创建子目录失败 ${subTaskDir}: ${e}`;
          }

          debugLog(`delegate_analysis: target=${target_agent} subDir=${subTaskDir}`, context.sessionID);

          // 3. 构造子会话 system 内容
          const systemContent = buildSubSessionSystem(target_agent, subTaskDir, parent_task_dir);

          // 4. 创建子会话
          if (!opencodeClient) {
            return `错误: OpenCode client 未初始化`;
          }

          let subSessionID: string;
          try {
            const createResult = await opencodeClient.session.create({
              body: {
                parentID: context.sessionID,
                title: `${description || subdir_name}: ${target_agent} 子任务`,
                // 禁止子 Agent 使用 question 工具提问用户
                // （子 Agent 在同步模式下运行，提问会阻塞且让用户困惑）
                permission: [{ permission: "question", action: "deny", pattern: "*" }],
              },
              query: { directory: context.directory },
            });

            if (createResult.error) {
              return `错误: 创建子会话失败 - ${JSON.stringify(createResult.error)}`;
            }

            subSessionID = (createResult.data as { id: string }).id;
            debugLog(`delegate_analysis: 子会话已创建 id=${subSessionID}`, context.sessionID);

            // 注册子会话到 sessions Map，使 system.transform hook 能处理它：
            // - 展开 {{buwai-rule:xxx}} 占位符（所有 agent prompt 都使用）
            // - 注入正确的环境信息（$AGENT_DIR 按目标 agent 映射）
            // 不设置 isSubSession 标记，因为 system.transform 的环境注入与
            // system 参数的注入是冗余但无害的（都提供相同的环境变量值）
            sessions.set(subSessionID, {
              createdAt: Date.now(),
              agentName: target_agent,
              primaryAgent: target_agent,
              systemTransformCount: 0,
            });
            // 为子会话写入 task session 映射，使子会话的日志路由到子任务目录
            try {
              mkdirSync(TASK_SESSIONS_DIR, { recursive: true });
              writeFileSync(
                join(TASK_SESSIONS_DIR, `${subSessionID}.json`),
                JSON.stringify({ task_dir: subTaskDir }),
              );
              taskDirCache.set(subSessionID, subTaskDir);
              debugLog(`delegate_analysis: 子会话 task session 映射已写入 dir=${subTaskDir}`, context.sessionID);
            } catch (e) {
              debugLog(`delegate_analysis: 写入 task session 映射失败: ${e}`, context.sessionID);
            }
            debugLog(`delegate_analysis: 子会话已注册到 sessions Map, agent=${target_agent}`, context.sessionID);
          } catch (e) {
            return `错误: 创建子会话异常 - ${e}`;
          }

          // 5. 异步发送任务（promptAsync 立即返回，不阻塞 tool execute）
          try {
            const promptResult = await opencodeClient.session.promptAsync({
              path: { id: subSessionID },
              body: {
                agent: target_agent,
                system: systemContent,
                parts: [{ type: "text", text: task_prompt }],
              },
            });

            if (promptResult.error) {
              await abortSubSession(subSessionID, "prompt_failed");
              return `错误: 发送任务失败 - ${JSON.stringify(promptResult.error)}`;
            }

            debugLog(`delegate_analysis: promptAsync 已发送 subSession=${subSessionID}`, context.sessionID);

            // 6. 轮询子会话状态直到完成或超时
            const pollError = await pollSubSession(context.sessionID, subSessionID);
            if (pollError) {
              return pollError;
            }

            // 7. 从子会话消息中提取结果
            const resultText = await fetchSubSessionResult(subSessionID, subTaskDir);
            debugLog(`delegate_analysis: 子任务完成 subSession=${subSessionID}`, context.sessionID);
            return resultText;
          } catch (e) {
            return `错误: 子 Agent 执行异常 - ${e}`;
          } finally {
            // 清理子会话的 sessions Map 条目（子会话已完成，不再需要 hook 处理）
            sessions.delete(subSessionID);
            debugLog(`delegate_analysis: 子会话已从 sessions Map 清理 id=${subSessionID}`, context.sessionID);
          }
        },
      }),
    },

    // 用户发送消息时触发（awaited，宿主等待完成）
    // 职责：记录 agentName + 设置主 session 的 primaryAgent
    // 注意：chat.message 是唯一能直接从 input.agent 获取 agent 名的 hook
    //       system.transform / tool.execute.before 的 input 无 agent
    //       但 requireSessionWithPrimary 可通过 session.get API 间接获取
    "chat.message": async (input) => {
      const agent = (input as { agent?: string })?.agent;
      // DEBUG: 诊断 OpenCode hook input 结构（确认后可删除）
      debugLog(`DEBUG chat.message INPUT keys=${Object.keys(input || {}).join(",")} agent=${agent ?? "无"}`);
      const sessionID = (input as { sessionID?: string })?.sessionID;
      if (!sessionID) {
        debugLog(`chat.message: 跳过 — 无 sessionID, agent=${agent}`);
        return;
      }

      let isValidAgent = true;
      if (!agent) {
        debugLog("chat.message: 跳过 — 无 agent", sessionID);
        isValidAgent = false;
      } else if (!PRIMARY_AGENTS.includes(agent)) {
        debugLog(
          `chat.message: 跳过 — agent=${agent} 不在 PRIMARY_AGENTS 中, sessionID=${sessionID}`,
          sessionID,
        );
        isValidAgent = false;
      }

      if (!isValidAgent) {
        sessions.delete(sessionID);
        nonPrimarySessions.add(sessionID);
        return;
      }

      // 清除非主缓存（agent 可能已切换回 PRIMARY）
      nonPrimarySessions.delete(sessionID);

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
    // 注意：output.system 每次请求都重建，不会累积
    //       每 10 次 LLM 请求注入一次完整环境信息，中间请求由 LLM 从对话历史获取路径值
    "experimental.chat.system.transform": async (input, output) => {
      const sessionID = (input as { sessionID?: string })?.sessionID;
      // DEBUG: 诊断 OpenCode hook input 结构（确认后可删除）
      debugLog(`DEBUG system.transform INPUT keys=${Object.keys(input || {}).join(",")} agent=${(input as { agent?: string })?.agent ?? "未传入"} sessionID=${sessionID}`, sessionID);
      const session = await requireSessionWithPrimary(
        "system.transform",
        sessionID,
      );
      if (!session) return;

      const agentName = session.agentName;

      // 占位符展开（每次 LLM 调用都执行，不受 shouldInject 控制）
      if (agentName) {
        const agentFile = join(AGENTS_DIR, `${agentName}.md`);
        if (hasBuwaiExtensionId(agentFile)) {
          // 匹配 {{buwai-rule:片段名}} — 片段名仅允许字母数字连字符下划线
          const regex = /\{\{buwai-rule:([a-zA-Z0-9_-]+)\}\}/g;
          for (let i = 0; i < output.system.length; i++) {
            // 快速跳过不含占位符的字符串，避免无谓的正则匹配
            if (!output.system[i].includes("{{buwai-rule:")) continue;
            output.system[i] = output.system[i].replace(regex, (_, name) => {
              const snippet = loadSnippet(name);
              if (snippet === null) {
                debugLog(`Snippet not found: ${name}`, sessionID);
                return _; // 保留原始占位符文本，不删除
              }
              debugLog(`Expanded snippet: ${name} (${snippet.length} chars)`, sessionID);
              return snippet;
            });
            // DEBUG: 打印替换完成后的完整内容，验证通过后注释掉
            // debugLog(`=== system[${i}] after expansion (${output.system[i].length} chars) ===\n${output.system[i]}`, sessionID);
          }
        }
      }

      // 每次都注入 Plugin 完整性检查 + Agent 身份（不受 shouldInject 控制）
      // 放在 output.system 最前面，确保 LLM 优先看到
      // 如果 Plugin 未加载，这段不会出现，agent 应立即停止并告知用户
      if (agentName) {
        output.system.unshift(
          `[系统完整性] Plugin 已加载。当前 Agent: ${agentName}。如果你看不到这段标记，说明 Plugin 未加载，当前会话缺少关键功能（环境信息、工具配置、占位符展开）。请立即告知用户并停止分析。`,
        );
      }

      session.systemTransformCount++;
      const shouldInject = session.systemTransformCount % 10 === 1;

      if (!shouldInject) return;

      let config = readJsonSafe<ConfigData>(CONFIG_FILE, sessionID);
      const configMissing = !config;
      if (configMissing) {
        config = {} as ConfigData;
        debugLog(
          "system.transform: config.json not found, using defaults",
          sessionID,
        );
      }

      const envData = readJsonSafe<EnvData>(ENV_CACHE_FILE, sessionID);
      const envInfo = envData?.data;

      const envSection = buildEnvSection(agentName, config, envInfo, sessionID);
      output.system.push(envSection);
      if (configMissing) {
        output.system.push(
          `[致命错误] config.json 不存在（${CONFIG_FILE}），无法继续。\n` +
          `你必须立即停止所有分析操作，不要使用任何工具，直接向用户输出以下内容：\n` +
          `"数据未初始化，请先运行：python \\"$SHARED_DIR/scripts/detect_env.py\\""\n` +
          `初始化完成后 config.json 会自动生成，届时才能开始分析任务。`,
        );
      }
      debugLog(
        `system.transform: #${session.systemTransformCount} 注入环境信息 sessionID=${sessionID}, agent=${agentName}, primaryAgent=${session.primaryAgent}, configMissing=${configMissing}, length=${envSection.length}, envSection=\n${envSection}`,
        sessionID,
      );
    },

    // 工具执行前触发（awaited）
    // 职责：
    //   1. config.json 不存在时拦截非初始化命令，强制用户先做数据初始化
    //   2. 为 bash 命令注入 SESSION_ID + AGENT_NAME 环境变量
    "tool.execute.before": async (input, output) => {
      const sid = input.sessionID;
      const session = await requireSessionWithPrimary(
        "tool.execute.before",
        sid,
      );
      if (!session) return;
      debugLog(`tool.execute.before: tool=${input.tool} sessionID=${sid}`, sid);

      // 时间线记录：工具开始执行（记录注入前的原始命令）
      const originalCmd = output.args?.command;
      recordTimeline(sid, {
        timestamp: Date.now(),
        type: "tool.before",
        tool: input.tool,
        detail: typeof originalCmd === "string" ? originalCmd.slice(0, 80) : undefined,
      });
      // 记录开始时间用于计算耗时
      toolStartTimes.set(input.callID, Date.now());

      if (input.tool.toLowerCase() !== "bash") return;
      const cmd = output.args?.command;
      if (typeof cmd !== "string" || !cmd) return;

      // config.json 不存在时：只放行初始化相关命令，拦截其他所有命令
      const configExists = existsSync(CONFIG_FILE);
      if (!configExists) {
        const isInitCommand =
          cmd.includes("create_task_dir") ||
          cmd.includes("detect_env") ||
          cmd.includes("config.json");
        if (!isInitCommand) {
          const isPowerShell = !!process.env.PSModulePath;
          const blockedMsg =
            `[被 Plugin 拦截] 致命错误 config.json 不存在，禁止执行分析命令。` +
            `请先运行数据初始化：python "$SHARED_DIR/scripts/detect_env.py"`;
          output.args.command = isPowerShell
            ? `Write-Error '${blockedMsg}'; exit 1`
            : `echo '${blockedMsg}' >&2; exit 1`;
          debugLog(`tool.execute.before: BLOCKED (no config.json) cmd=${cmd.slice(0, 80)}`, sid);
          return;
        }
      }

      const isUnix = !!process.env.SHELL || !!process.env.MSYSTEM;
      const isPowerShell = !isUnix && !!process.env.PSModulePath;
      const agentName = session.agentName || "";
      if (isUnix) {
        // bash 单引号转义：' → '\''（结束引号→转义单引号→重新开始引号）
        const safeSid = sid.replace(/'/g, "'\\''");
        const safeAgent = agentName.replace(/'/g, "'\\''");
        output.args.command = `SESSION_ID='${safeSid}' AGENT_NAME='${safeAgent}' ${cmd}`;
      } else if (isPowerShell) {
        // PowerShell 单引号转义：' → ''（两个单引号）
        const safeSid = sid.replace(/'/g, "''");
        const safeAgent = agentName.replace(/'/g, "''");
        output.args.command = `$env:SESSION_ID='${safeSid}'; $env:AGENT_NAME='${safeAgent}'; ${cmd}`;
      } else {
        // cmd.exe 双引号内不需要转义单引号
        output.args.command = `set "SESSION_ID=${sid}" && set "AGENT_NAME=${agentName}" && ${cmd}`;
      }
      debugLog(`injected: ${output.args.command.slice(0, 120)}`, sid);
    },

    // 工具执行后触发（fire-and-forget）
    // 职责：记录工具执行结果，供 evolve agent 事后验证
    "tool.execute.after": async (input, output) => {
      const sid = input.sessionID;
      const session = await requireSessionWithPrimary(
        "tool.execute.after",
        sid,
      );
      if (!session) return;

      const toolName = input.tool;

      // 时间线记录：工具执行完成（计算耗时）
      const startTime = toolStartTimes.get(input.callID);
      toolStartTimes.delete(input.callID);
      recordTimeline(sid, {
        timestamp: Date.now(),
        type: "tool.after",
        tool: toolName,
        duration: startTime ? Date.now() - startTime : undefined,
      });

      // 对自定义工具记录完整结果，对内置工具只记录调用
      if (toolName === "delegate_analysis") {
        const result = typeof output.output === "string"
          ? output.output
          : JSON.stringify(output.output);
        const summary = result.length > 500
          ? result.slice(0, 500) + `...(truncated, total ${result.length} chars)`
          : result;
        debugLog(
          `tool.execute.after: tool=${toolName} result=${summary}`,
          sid,
        );
      } else {
        debugLog(`tool.execute.after: tool=${toolName}`, sid);
      }
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

      // 时间线记录：session 状态变化和错误
      if (sessionID && PRIMARY_AGENTS.includes(
        sessions.get(sessionID)?.primaryAgent || ""
      )) {
        if (event.type === "session.status" || event.type === "session.idle") {
          recordTimeline(sessionID, {
            timestamp: Date.now(),
            type: "session.status",
            detail: event.type,
          });
          // session idle 时 flush 时间线 buffer
          if (event.type === "session.idle") {
            flushTimeline(sessionID);
          }
        }

        if (event.type === "session.error" && props.error) {
          recordTimeline(sessionID, {
            timestamp: Date.now(),
            type: "session.error",
            detail: String(props.error).slice(0, 80),
          });
        }

        // 心跳：Shell 有输出更新时记录（表示有活跃的工具执行）
        if (event.type === "message.part.updated" && props.part?.type === "text") {
          recordTimeline(sessionID, {
            timestamp: Date.now(),
            type: "heartbeat",
          });
        }
      }
    },
  };
};
