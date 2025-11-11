# GhidraMCP

一个Ghidra插件，实现了模型上下文协议（MCP），用于AI辅助的二进制分析。

## 概述

Ghidra MCP通过模型上下文协议（MCP）结合了Ghidra强大的逆向工程能力与AI助手之间的差距。该插件使AI模型能够连接到Ghidra并协助完成二进制分析任务，从而使逆向工程更加高效和易于访问。

## 特性

- **AI驱动的二进制分析**：通过模型上下文协议将AI助手连接到Ghidra
- **自然语言界面**：用简单的英语提出关于二进制文件的问题
- **深入的代码洞察**：检索详细的函数信息和反编译代码
- **二进制结构分析**：探索导入、导出和内存布局
- **自动化安全分析**：获取有关潜在安全漏洞的AI辅助见解
- **基于套接字的架构**：Ghidra与AI助手之间的高性能通信
- **跨平台兼容性**：可在Ghidra支持的所有平台上运行

## 安装

### 先决条件

- Ghidra 11.2.1+
- Java 17或更新版本
- Python 3.8+（用于桥接脚本）

### 步骤

1. 从[发布](https://github.com/yourusername/GhidraMCP/releases)页面下载最新的发布ZIP文件
2. 打开Ghidra
3. 导航到`文件 > 安装扩展`
4. 单击“+”按钮并选择下载的ZIP文件
5. 重新启动Ghidra以完成安装
6. 通过转到`文件 > 配置 > 其他`并选中“MCPServerPlugin”旁边的框来启用扩展

## 用法

### 启动MCP服务器

在启用插件后打开Ghidra项目时，服务器会自动启动。默认情况下，它在以下位置运行：
- 主机：`localhost`
- 端口：`8765`

您可以通过检查Ghidra控制台中的以下消息来验证服务器是否正在运行：
```
MCP服务器已在端口8765上启动
```

### 与AI助手连接

#### 与Claude连接

要将Claude连接到GhidraMCP插件：

1. 安装MCP桥接脚本：
   ```bash
   pip install FastMCP
   ```

2. 将以下配置添加到您的Claude MCP设置中：
   ```json
   {
     "mcpServers": {
       "ghidra": {
         "command": "python",
         "args": ["PATH-TO-REPO/GhidraMCP/ghidra_server.py"]
       }
     }
   }
   ```

桥接脚本在Ghidra和Claude之间创建连接，通过自然语言实现实时二进制分析。

### 可用工具

该插件通过MCP界面公开了几个强大的功能：

| 工具 | 描述 |
|------|-------------|
| `get_function(address, decompile=False)` | 检索特定地址处的函数的详细信息 |
| `analyze_binary(question)` | 用自然语言提问关于加载的二进制文件的问题 |
| `get_imports()` | 列出二进制文件中的所有导入函数 |
| `get_exports()` | 列出二进制文件中的所有导出函数 |
| `get_memory_map()` | 获取二进制文件的内存布局 |
| `connect_to_ghidra(host, port)` | 连接到特定的Ghidra实例 |
| `rename_function(current_name, new_name)` | 按当前名称重命名函数 |
| `rename_data(address, new_name)` | 重命名特定地址处的数据标签 |
| `extract_api_call_sequences(address)` | 从函数中提取API调用以进行安全分析 |
| `identify_user_input_sources()` | 在二进制文件中查找潜在的用户输入源 |
| `generate_call_graph(address, max_depth=3)` | 生成函数调用的分层表示 |
| `identify_crypto_patterns()` | 检测二进制文件中的加密实现 |
| `find_obfuscated_strings()` | 定位可能被混淆的字符串 |

### 查询示例

以下是您可以通过与MCP兼容的AI客户端提出的问题示例：

- “此二进制文件中使用了哪些加密算法？”
- “您能向我展示地址为0x401000的函数的反编译代码吗？”
- “此恶意软件进行了哪些可疑的API调用？”
- “根据其导入和导出解释此二进制文件的用途。”
- “此程序中的身份验证机制如何工作？”
- “此代码中是否存在任何潜在的缓冲区溢出漏洞？”
- “此二进制文件建立了哪些网络连接？”
- “您能将此函数重命名为更具描述性的名称吗？”
- “向我显示所有可能被利用的潜在用户输入源。”
- “为主函数生成调用图。”

## 高级用法

### 安全分析功能

GhidraMCP为以安全为重点的分析提供了专门的工具：

#### API调用序列分析
从函数中提取和分类外部API调用以进行安全分析。这有助于识别潜在的危险函数并了解它们的交互。

#### 用户输入源
识别外部数据进入程序的入口点，这对于漏洞评估和了解攻击面至关重要。

#### 调用图生成
创建结构化的调用图以了解执行流程、跟踪数据传播并识别潜在的攻击路径。

#### 加密模式检测
识别加密实现，包括标准算法（AES、RSA等）和基于代码模式的自定义实现。

#### 混淆字符串检测
查找可能通过XOR编码或逐字符构造等技术混淆的字符串。

### 自定义配置

您可以通过编辑`MCPServerPlugin.java`文件来修改服务器端口：

```java
server.setPort(YOUR_CUSTOM_PORT);
```

### 与分析工作流集成

GhidraMCP可以集成到您现有的分析工作流中：

1. 使用Ghidra的标准分析功能识别感兴趣的区域
2. 通过GhidraMCP利用AI辅助以获得更深入的理解
3. 将AI见解与您的手动分析相结合
4. 根据AI见解重命名函数和数据以提高可读性

## 从源代码构建

要从源代码构建插件：

1. 克隆此存储库
   ```bash
   git clone https://github.com/yourusername/GhidraMCP.git
   ```

2. 按照[Ghidra开发人员指南](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md)中的说明设置Ghidra开发环境

3. 设置`GHIDRA_INSTALL_DIR`环境变量：
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

4. 使用Gradle构建：
   ```bash
   ./gradlew buildExtension
   ```

5. 扩展ZIP文件将在`dist`目录中创建

## 故障排除

### 常见问题

- **连接问题**：确保Ghidra实例正在运行并且插件已启用
- **端口冲突**：如果端口8765已被使用，请在插件配置中修改端口
- **桥接脚本错误**：检查是否已使用`pip install FastMCP`安装了所有必需的Python软件包
- **分析函数返回空结果**：如果二进制文件不包含相关模式，某些安全分析函数可能会返回空结果

### 日志

检查以下日志以进行故障排除：
- Ghidra控制台中的服务器端消息
- `ghidra_mcp_bridge.log`中的桥接脚本问题

## 贡献

欢迎贡献！请随时提交问题或拉取请求。

1. Fork存储库
2. 创建您的功能分支：`git checkout -b feature/amazing-feature`
3. 提交您的更改：`git commit -m 'Add some amazing feature'`
4. 推送到分支：`git push origin feature/amazing-feature`
5. 打开一个拉取请求


## 致谢

- [美国国家安全局（NSA）](https://github.com/NationalSecurityAgency/ghidra)开发了Ghidra
- [模型上下文协议](https://modelcontextprotocol.io/)社区
- 本项目的所有贡献者

---

*GhidraMCP与NSA或Ghidra项目无关，也未得到其认可。*