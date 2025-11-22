
# 🛡️ NetSentinel AI - 华为网络设备本地 AI 智能巡检系统



## 简介

**NetSentinel AI** 是一个基于 **Ollama** 本地大模型和 **Python/Streamlit**（或 Gradio）构建的华为网络设备智能巡检系统。它能够批量连接华为交换机（S57/S67/S127 等系列），自动执行预设指令集收集巡检日志，并调用本地 AI 大模型对原始日志进行**深度智能分析**，生成专业、可读性高的 Markdown 格式巡检报告。

本项目旨在提供一个**完全本地化、零数据泄露风险、高效率**的解决方案，替代传统人工分析巡检报告的耗时工作。

### 核心功能

  * **完全本地运行：** 依赖 Ollama，所有数据采集和 AI 推理都在本地完成，确保网络和数据安全。
  * **批量设备巡检：** 支持多台华为设备（通过 IP/用户名/密码）并发进行数据采集。
  * **智能分析报告：** AI 模型（如 Qwen、Mistral 等）将原始日志转化为结构清晰、包含风险点、原因分析和优化建议的中文 Markdown 报告。
  * **双模式支持：** 提供 Streamlit (数据存档) 和 Gradio (快速 Web 界面) 两种运行脚本。
  * **错误纠正优化：** 针对大模型生成 JSON 格式困难的问题（如早期版本遇到的 `JSON ERROR`），V8.x 版本已优化为更可靠的**自由格式 Markdown 报告**输出。

-----

## 🚀 部署指南

本项目依赖 **Python 3.8+**、**Ollama** 和相应的 Python 库。

### 步骤 1: 安装 Ollama 与大模型

1.  **安装 Ollama：**
    访问 [Ollama 官网](https://ollama.com/) 下载并安装适用于您操作系统的版本（Windows/macOS/Linux）。

2.  **拉取推荐模型：**
    在终端中运行以下命令，拉取一个具备良好中文理解和代码分析能力的大模型（例如 Qwen 或 Deepseek）：

    ```bash
    ollama run deepseek-r1:14b
    ```

    确保 Ollama 服务 (`http://localhost:11434`) 在后台运行。

### 步骤 2: 安装 Python 依赖

克隆本项目到本地，并安装所需的 Python 库：

安装依赖
pip install streamlit ...
```

> **注意：** 主要依赖包括 `streamlit`, `netmiko`, `requests`, `pandas` (Streamlit版) 和 `gradio` (Gradio版)。

-----

## 💻 使用方法


```bash
streamlit run app.py
```

1.  **⚙️ 设备管理：** 首先在“设备管理”页添加您的华为设备 IP、用户名和密码。
2.  **💻 智能巡检：** 切换到“智能巡检”，选择本地 Ollama 模型，点击 **`🚀 启动全网智能巡检`**。
3.  **结果查看：** 程序将先多线程采集日志，然后调用 AI 模型进行批处理分析，最终结果和原始日志可在 **`💾 历史档案`** 中查看和下载。



本系统由AI生成
