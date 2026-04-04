# IDA Pro 插件脚本

本目录存放基于 [IDAPython](https://hex-rays.com/products/ida-support/idapython_docs/) 的 IDA Pro 插件脚本，用于辅助移动端逆向分析。

## 目录结构

```
├── main.py          # 入口脚本（占位）
├── .venv/           # Python 虚拟环境
└── README.md
```

## 编码规范

遵循 [IDAPython 官方示例规范](file:///Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/README.md)，要点如下：

- **禁止使用 `idc.py`**：其部分操作语义模糊，优先使用各功能模块（如 `idautils`、`idabytes` 等）
- **禁止使用 `idaapi`**：直接 import 具体模块，避免隐藏符号来源，保持代码按模块归属清晰
- **禁止 `from <module> import <name>`**：统一使用 `import <module>` + `module.name` 引用，便于识别符号来源
- **字符串使用双引号**：所有字符串字面量默认使用 `""`，除非字符串本身包含 `"` 且转义后影响可读性

### 脚本文件头

每个脚本文件必须包含规范的 docstring 头部：

```python
"""summary: 一句话概述脚本功能（不以句号结尾）
描述信息，详细说明脚本用途、使用方法等。
"""
```

> `summary:` 首选 `list something...` 形式，而非 `listing something...`。

## 参考资源

- **IDAPython 示例索引**：[index.md](file:///Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/index.md)
- **IDAPython 示例源码**：`/Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples`
- **IDAPython 官方文档**：https://hex-rays.com/products/ida/support/idapython_docs/
