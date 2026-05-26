# 需求: Plugin 强制检查 coordinator 委托行为

## §1 背景与目标

**来源**: 任务 `20260526_223243_ee92` 中 coordinator 完成 WebCTF 知识沉淀但未调用 `delegate_analysis` 分发子任务。直接在 coordinator 自己的上下文中完成了所有工作，跳过了阶段 1 的委托流程。

**痛点**: 
- coordinator 的委托规则是软约束（prompt 中描述），实际执行时可能被忽略
- 没有硬性检查机制来捕获违规行为
- 用户需要手动审查 task_dir 结构才能发现问题

**预期收益**:
- 准确度: 捕获 coordinator 跳过委托的违规行为，注入警告让其纠正
- 上下文: 不增加额外调用（检查在 system.transform 中完成，零额外开销）
- 轮次: coordinator 在下一轮就能看到警告并纠正

## §2 技术方案

### 检测逻辑

在 Plugin 的 `system.transform` hook 中（`shouldInject` 门控之前）添加检查：

1. 条件：`agentName === "security-coordinator"` 且 `!session.delegationCheckCompleted`
2. 获取 task_dir（通过已有的 `getTaskDir()`）
3. 如果 task_dir 下不存在 `summary.md`：跳过（coordinator 尚未开始写 summary，下一轮再检查）
4. 如果 task_dir 下存在 `summary.md`：
   - 检查 task_dir 下是否有子目录（子 agent 工作目录）
   - 如果没有子目录：读取 summary.md 检查是否包含降级说明关键词
   - 如果既没有子目录也没有降级说明：注入警告到 `output.system`
5. summary.md 存在时（无论是否触发警告），设置 `delegationCheckCompleted = true`（避免重复检查）

### 改动文件

| 文件 | 改动内容 |
|------|---------|
| `plugins/security-analysis.ts` | SessionData 接口加 `delegationCheckCompleted` 字段；import 加 `readdirSync`；system.transform 中加检查逻辑 |

### 判定关键词

summary.md 中包含以下任一关键词视为有降级说明：
- "降级"
- "delegate"
- "子 agent"

## §3 实现规范

### §3.1 实施步骤

**步骤 1. SessionData 接口扩展**
- 文件: `plugins/security-analysis.ts`
- 预估行数: 2 行
- 验证点: TypeScript 语法检查通过

**步骤 2. 添加 readdirSync import**
- 文件: `plugins/security-analysis.ts`
- 预估行数: 1 行
- 验证点: TypeScript 语法检查通过

**步骤 3. system.transform 中添加检查逻辑**
- 文件: `plugins/security-analysis.ts`
- 预估行数: ~45 行
- 验证点: TypeScript 语法检查通过 + 审计通过

依赖: 步骤 1、2 先于步骤 3

## §4 验收标准

### 功能验收
- coordinator 在 task_dir 下有 summary.md + 无子目录 + 无降级说明 → 警告被注入
- coordinator 在 task_dir 下有 summary.md + 有子目录 → 无警告
- coordinator 在 task_dir 下有 summary.md + 无子目录 + 有降级说明 → 无警告
- 非 coordinator agent → 检查不执行
- `delegationCheckCompleted` 设置后不重复检查

### 回归验收
- 其他 agent 的 system.transform 行为不受影响
- shouldInject 机制不受影响
- 环境注入不受影响

### 架构验收
- 检查逻辑在 shouldInject 门控之外（每轮可执行）
- 检查逻辑对非 coordinator agent 零开销（if 条件短路）
- 不引入新的外部依赖

## §5 与现有需求文档的关系

- 独立于 `2026-05-26-unify-python-cmd-venv.md`（Python 路径统一）
- 独立于 `2026-05-26-plugin-inject-python-cmd.md`（Plugin 注入 $PYTHON_CMD）
- 补充 `2026-05-22-security-coordinator.md`（coordinator 架构）的执行约束
