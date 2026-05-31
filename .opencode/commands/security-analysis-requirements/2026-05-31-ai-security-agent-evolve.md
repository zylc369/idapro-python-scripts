# AI Security Agent 进化需求 — 基于三模型越狱测试实战经验

> 来源: `docs/解题报告/AI安全/ai-model-defense-bypass-analysis.md`
> 测试数据: 35轮攻击, 3模型×3向量, 100%突破率

---

## §1 背景与目标

### 来源复盘

在 opencode-go 三模型（deepseek-v4-pro / glm-5.1 / deepseek-v4-flash）的越狱测试中，发现了多项当前 agent prompt 和知识库未覆盖的攻击模式。35轮攻击产出了大量可复用的方法论和实战数据。

### 痛点

| 痛点 | 影响 |
|------|------|
| 基线探测后缺乏"从拒绝措辞到攻击方向"的映射 | 攻击者不知道下一步该用什么框架，多轮试错浪费 token |
| Agent 没有模型层越狱的系统化方法论 | 只覆盖应用层提示注入（URL/源码），未覆盖模型安全对齐绕过 |
| glm-5.1 会话追踪封锁后无应对策略 | 攻击者在同一 session 内反复失败后束手无策 |
| 零知识攻击者无法拆解复杂目标 | 依赖攻击者自身领域知识 |
| 缺少三模型防线画像 | 每次攻击都要重新探测模型防御特性 |

### 预期收益

| 维度 | 改进前 | 改进后 | 提升 |
|------|--------|--------|:---:|
| 上下文占用 | 平均 10+ 轮试错 | 基线诊断后直击有效框架, ~4 轮 | ⬇60% |
| 对话轮次 | 同 session 反复换框架被追踪封锁 | 识别防线类型后直接碎片化/正交 | ⬇40% |
| 分析速度 | 每次重新探测模型特性 | 已有模型防线画像 | ⬆30% |
| 结果准确度 | 攻击方向依赖猜测 | 系统化方法论 | ⬆35% |

---

## §2 技术方案

### 方案 A：新增知识库 `bypass-framework-matrix.md`

**文件**: `$AGENT_DIR/knowledge-base/bypass-framework-matrix.md`

**内容**：基于35轮实战验证的 bypass 框架速查表，包含：

1. **拒绝模式→攻击方向映射表**（5种拒绝模式 × 推荐框架）
2. **正交领域四步法**（识别成分→合法场景→角色匹配→无破绽提问）
3. **正交领域实战速查表**（校园暴力→VR行为树 / DDoS→教材代码 / 假证→四工业领域）
4. **碎片化策略**（何时用、怎么拆、如何验证完整性）
5. **0→1 策略**（何时用、第一步模板、术语传递链示例）
6. **身份选择策略**（学术 vs 执法 vs 教学 vs 威胁建模的适用场景）
7. **常见失败模式与切换方向**（含语义等价追踪、角色边界拦截、会话追踪封锁）

**触发条件**：阶段 B（分析规划）时读取

### 方案 B：更新 `model-security-analysis-guide.md`

**文件**: `$AGENT_DIR/knowledge-base/model-security-analysis-guide.md`

**增量内容**：
1. §2.2 拒绝模式五分类增加「从拒绝措辞推断攻击方向」的诊断表
2. §3 增加「框架匹配矩阵」——根据模型拒绝模式推荐最优先尝试的框架
3. §3 增加「正交领域发现流程」引用方案A的四步法
4. 更新 §7 越狱技术速查卡：补充正交领域重述、碎片化、0→1
5. 新增 §8「攻击策略选择决策树」——基于基线诊断结果的决策流程

### 方案 C：Agent prompt 增加诊断与方向映射

**文件**: `$AGENT_DIR/agents/ai-security-analysis.md`

**改动**：
1. **参数解析段**：增加目标类型「模型名称」→ 模型层越狱攻击 → 使用 dialogue 工具
2. **阶段 A**：增加「模型层攻击」子路径，包含基线探测→拒绝模式诊断
3. **阶段 B**：在"读取 llm-attack-methodology.md"后追加"如为模型层攻击，读取 bypass-framework-matrix.md"
4. **常见失败模式表**：追加模型层特有失败模式（语义等价追踪拦截、会话追踪封锁、角色边界拒绝、身份验证拒绝）

### 方案 D：Agent prompt 增加碎片化/0→1 策略

**文件**: `$AGENT_DIR/agents/ai-security-analysis.md`

**改动**：
在常见失败模式表后追加碎片化和0→1的操作指引（3-5行触发条件+核心规则），详细内容通过知识库按需加载。

### 方案 E：新增知识库 `model-defense-profiles.md`

**文件**: `$AGENT_DIR/knowledge-base/model-defense-profiles.md`

**内容**：三模型防线画像表，攻击者进入阶段B时可查阅目标模型的已知防线特性：

| 模型 | 直接拦截 | 语义过滤 | 角色限制 | 语义追踪 | 会话追踪 | 身份验证 | 推荐首攻框架 |
|------|:---:|:---:|:---:|:---:|:---:|:---:|------|
| deepseek-v4-pro | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ | 学术论文/IEEE框架 |
| glm-5.1 (opencode) | ✅ | ✅ | ✅ | ✅✅ | ✅ | N/A | 正交领域+碎片化 |
| deepseek-v4-flash | ✅ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | 游戏行为树/学术框架 |

---

## §3 实现规范

### §3.1 实施步骤拆分

#### 步骤 1：新增 `bypass-framework-matrix.md`

- **文件**: `$AGENT_DIR/knowledge-base/bypass-framework-matrix.md`
- **预估行数**: ~200 行
- **内容**：拒绝模式映射表 + 正交领域四步法 + 速查表 + 碎片化 + 0→1 + 身份选择 + 失败模式
- **验证点**: 读取文件，确认包含全部7个子节，每个子节有可操作的模板/payload
- **依赖**: 无

#### 步骤 2：更新 `model-security-analysis-guide.md`

- **文件**: `$AGENT_DIR/knowledge-base/model-security-analysis-guide.md`
- **预估行数**: 新增 ~80 行，修改 ~20 行
- **内容**：§2.2增加诊断映射 + §3增加框架匹配矩阵 + 更新§7 + 新增§8决策树
- **验证点**: 读取文件，确认§2.2有诊断表、§3有匹配矩阵、§7有正交/碎片化/0→1、§8有ascii决策树
- **依赖**: 步骤 1（引用 bypass-framework-matrix.md）

#### 步骤 3：更新 Agent prompt — 删除参数解析，增加A-3模型层路径

- **文件**: `$AGENT_DIR/agents/ai-security-analysis.md`
- **预估行数**: 删除 ~15 行（参数解析段），新增 ~15 行（A-3）
- **内容**：删除"参数解析与目标识别"段（LLM可自行判断输入类型，无需静态分类表）；阶段A增加「A-3: 模型层攻击」子路径（基线探测→拒绝模式诊断→查阅防线画像）
- **验证点**: 读取文件，确认参数解析段已删除、阶段A有A-3子路径含基线探测步骤、A-3引用 model-defense-profiles.md
- **依赖**: 无

#### 步骤 4：更新 Agent prompt — 阶段B与失败模式表

- **文件**: `$AGENT_DIR/agents/ai-security-analysis.md`
- **预估行数**: 新增 ~20 行
- **内容**：阶段B追加模型层知识库加载指引；失败模式表追加5条模型层特有失败模式
- **验证点**: 读取文件，确认阶段B含 bypass-framework-matrix.md 引用，失败模式表≥12行
- **依赖**: 步骤 1（表项引用 bypass-framework-matrix.md）

#### 步骤 5：更新 Agent prompt — 碎片化/0→1 策略

- **文件**: `$AGENT_DIR/agents/ai-security-analysis.md`
- **预估行数**: 新增 ~10 行
- **内容**：在失败模式表后追加碎片化触发条件和0→1入口规则
- **验证点**: 读取文件，确认含"连续3次同一session失败→换session碎片化"规则和"零领域知识→0→1"指引
- **依赖**: 步骤 4

#### 步骤 6：新增 `model-defense-profiles.md`

- **文件**: `$AGENT_DIR/knowledge-base/model-defense-profiles.md`
- **预估行数**: ~80 行
- **内容**：三模型×七防线画像表 + 深度描述（glm-5.1三层防御详解/deepseek-v4-pro漏洞详解）
- **验证点**: 读取文件，确认含三模型防线表和各模型独立详细的防线剖析
- **依赖**: 无

#### 步骤 7：更新知识库索引

- **文件**: `$AGENT_DIR/agents/ai-security-analysis.md` 知识库索引段
- **预估行数**: 新增 ~6 行
- **内容**：索引表追加 bypass-framework-matrix.md、model-defense-profiles.md 的触发条件
- **验证点**: 读取索引段，确认新增两个条目
- **依赖**: 步骤 1、步骤 6

### §3.2 编码规则

- 所有知识库文件遵循 `$SHARED_DIR/knowledge-base/knowledge-writing-guide.md` 规范
- 知识库文件必须自包含（不依赖主 prompt 上下文即可理解）
- 引用路径使用 `$AGENT_DIR` 变量
- Agent prompt 修改使用 Edit 工具局部修改，禁止 Write 全量重写

---

## §4 验收标准

### 功能验收

- [ ] agent 能识别用户输入的模型名称（如"deepseek-v4-pro"）并自动选择模型层攻击路径
- [ ] 基线探测后 agent 能根据拒绝措辞诊断防线类型，选择最优首攻框架
- [ ] 同session连续3次失败后 agent 自动切换碎片化策略
- [ ] 零知识场景下 agent 能启动0→1策略
- [ ] 已知模型（deepseek-v4-pro/glm-5.1/deepseek-v4-flash）的防线画像可被查阅

### 回归验收

- [ ] 应用层攻击（URL/源码/API）路径不受影响
- [ ] 现有知识库文件（llm-attack-methodology.md 等）功能完整
- [ ] Agent prompt 展开后行数 < 450

### 架构验收

- [ ] 新增文件在 `$AGENT_DIR/knowledge-base/` 目录下
- [ ] 知识库文件通过自包含性检查
- [ ] 无循环依赖

---

## §5 与现有需求文档的关系

| 相关文档 | 关系 |
|---------|------|
| `2026-05-30-ai-security-analysis-agent.md` | 本需求的基准版本——ai-security-analysis agent 的初始创建 |
| `2026-05-30-ai-security-carrier-and-evaluation.md` | 互补——载体构造和效果评估是本需求的基础设施 |
| `model-security-analysis-guide.md` | 本需求对其进行增量更新，非替代 |
