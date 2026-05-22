# 验证步骤: security-coordinator 复合任务编排

## 前置条件

- OpenCode 已启动且 Plugin 加载成功
- 测试样本: `examples\android\新京报_5.6.5.apk`
- 已配置 IDA Pro 路径（`~/bw-security-analysis/config.json` 中 `ida_path`）
- 已安装 apktool、jadx 等移动端工具

---

## 阶段 1: 静态验证 ✅ 已通过（由 evolve agent 自动完成）

| 检查项 | 结果 |
|--------|------|
| Agent 文件存在 | ✅ |
| Frontmatter (description/mode/buwai-extension-id) | ✅ |
| Plugin 语法 (`node --check`) | ✅ |
| Plugin 内容 (coordinator 常量 / delegate_analysis / VALID_SUB_AGENTS / 压缩保留) | ✅ |
| 现有文件未修改 (git status) | ✅ |
| Agent prompt 237 行 < 450 | ✅ |

---

## 阶段 2: OpenCode 启动验证（需要你操作）

### 2.1 启动 OpenCode 并切换到 security-coordinator

1. 启动 OpenCode
2. 按 Tab 键切换 Agent
3. 在 Agent 列表中找到 `security-coordinator` 并选择

**预期结果**:
- Agent 列表中可见 `security-coordinator`
- 切换后系统提示中包含 Coordinator 的角色描述
- 系统提示中包含 `delegate_analysis` 工具的描述

**如果失败**:
- Agent 不在列表 → 检查 `.opencode/agents/security-coordinator.md` 是否存在
- Plugin 未加载 → 检查 `.opencode/plugins/security-analysis.ts` 语法，查看 OpenCode 日志

### 2.2 检查 Plugin 日志

查看 `~/bw-security-analysis/logs/security-coordinator.log`（如果文件存在）。

预期看到:
```
=== SecurityAnalysisPlugin loaded ===
```

---

## 阶段 3: 简单分发测试（单子任务）

### 3.1 发送一个单领域任务

在 security-coordinator 中输入:

```
分析 APK 文件 examples\android\新京报_5.6.5.apk 的整体结构
只需要 mobile-analysis 做基础解包和 AndroidManifest 分析即可
```

**预期结果**:

1. Coordinator 输出分析方案（包含 1 个子任务）
2. 方案内容类似:

```
| # | 子任务 | Agent | 依赖 | 说明 |
|---|--------|-------|------|------|
| 1 | APK 基础分析 | mobile-analysis | 无 | 解包+AndroidManifest+native库列表 |
```

3. 等你确认后，Coordinator 调用 `delegate_analysis` 工具
4. 工具执行过程:
   - 创建父任务目录
   - 创建子目录 `.../mobile-analysis/`
   - 创建子会话
   - 等待子 Agent 完成
5. Coordinator 收到摘要并展示给你

**验证点**:
- [ ] Coordinator 输出了分析方案并等待确认
- [ ] 调用了 `delegate_analysis` 工具（在 OpenCode 的工具调用日志中可见）
- [ ] 子会话被创建（在 OpenCode 的 session 列表中可见新 session）
- [ ] 子 Agent（mobile-analysis）执行了 APK 解包
- [ ] 子目录被创建: `~/bw-security-analysis/workspace/<timestamp>_<rand>/mobile-analysis/`
- [ ] 子目录中有中间输出文件（如 unpacked/ 目录）
- [ ] Coordinator 收到了结构化摘要
- [ ] 摘要中包含"分析摘要"、"关键发现"、"报告路径"

**如果失败**:
- Coordinator 没有调用 delegate_analysis → 检查系统提示中是否有工具描述；可能是 LLM 没有识别到工具
- 工具报"OpenCode client 未初始化" → Plugin 加载失败，检查日志
- 工具报"创建子会话失败" → OpenCode SDK session API 问题
- 子 Agent 执行失败 → 检查子 Agent 的日志

---

## 阶段 4: 复合任务测试（多子任务）

### 4.1 发送复合分析任务

在 security-coordinator 中输入:

```
对 APK 文件 examples\android\新京报_5.6.5.apk 进行全面安全分析:
1. 先用 mobile-analysis 做整体解包分析（AndroidManifest、权限、组件、native库列表）
2. 然后根据第1步发现的 native .so 文件，用 binary-analysis 做其中一个 .so 的基础逆向分析
```

**预期结果**:

1. Coordinator 输出分析方案，包含 2 个子任务:

```
| # | 子任务 | Agent | 依赖 | 说明 |
|---|--------|-------|------|------|
| 1 | APK 整体解包 | mobile-analysis | 无 | 解包+AndroidManifest+native库 |
| 2 | .so 基础逆向 | binary-analysis | 1 | 分析第1步发现的native库 |
```

2. 确认后，Coordinator 先分发子任务 1（mobile-analysis）
3. 子任务 1 完成后，Coordinator 读取摘要
4. Coordinator 根据摘要中发现的 .so 文件路径，构造子任务 2 的 task_prompt
5. 分发子任务 2（binary-analysis），prompt 中包含子任务 1 发现的 .so 路径
6. 子任务 2 完成后，Coordinator 汇总输出

**验证点**:
- [ ] 方案包含 2 个子任务且有正确的依赖关系
- [ ] 子任务按顺序执行（先 1 后 2）
- [ ] 子任务 2 的 task_prompt 包含子任务 1 的发现（.so 文件路径）
- [ ] 两个子目录都被创建: `.../mobile-analysis/` 和 `.../binary-analysis/`
- [ ] 两个子目录中都有各自 Agent 的输出文件
- [ ] Coordinator 最终输出汇总报告
- [ ] 父任务目录结构类似:

```
~/bw-security-analysis/workspace/20260522_HHMMSS_xxxx/
├── mobile-analysis/
│   ├── env.json
│   ├── unpacked/         (apktool 解包输出)
│   └── ...               (其他 mobile-analysis 输出)
├── binary-analysis/
│   ├── initial.json      (idat 初始分析输出)
│   ├── initial.log
│   └── ...               (其他 binary-analysis 输出)
└── summary.md            (Coordinator 汇总报告)
```

**如果失败**:
- Coordinator 没有传递子任务 1 的发现给子任务 2 → Coordinator prompt 的 task_prompt 构造指引不够清晰，需要优化 prompt
- 子任务 2 的 idat 调用失败 → 检查 .so 文件路径是否正确，检查 IDA Pro 配置
- 子任务 2 跳过了环境检测 → 检查 system 注入内容是否正确

---

## 阶段 5: 结果质量检查

### 5.1 检查子 Agent 的结构化摘要格式

在 Coordinator 的输出中找到子 Agent 返回的摘要，确认包含:

- [ ] `## 分析摘要` — 一句话结论
- [ ] `## 关键发现` — 列表格式
- [ ] `## 报告路径` — 磁盘路径
- [ ] `## 执行统计` — 耗时和工具调用次数

### 5.2 检查子 Agent 跳过了任务目录创建

子 Agent 的输出中不应出现 `create_task_dir.py` 的调用记录。

- [ ] 子 Agent 没有调用 `create_task_dir.py`
- [ ] 子 Agent 的 `$TASK_DIR` 是父目录下的子目录

### 5.3 检查 Coordinator 汇总报告

- [ ] Coordinator 写入了 `$TASK_DIR/summary.md`
- [ ] 报告包含总体结论、各领域发现、关联发现、报告路径

---

## 验证结果汇总

完成所有阶段后，填写此表:

| 阶段 | 验证项 | 结果 | 备注 |
|------|--------|------|------|
| 1 | 静态验证 | ✅ 通过 | evolve agent 已自动完成 |
| 2 | OpenCode 启动 | ⬜ 通过 / ⬜ 失败 | |
| 3 | 单子任务分发 | ⬜ 通过 / ⬜ 失败 | |
| 4 | 复合任务分发 | ⬜ 通过 / ⬜ 失败 | |
| 5 | 结果质量 | ⬜ 通过 / ⬜ 失败 | |

**如果任何阶段失败，请将失败现象和 OpenCode 日志反馈给我，我会定位并修复。**
