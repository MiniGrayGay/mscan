# MScan 本地运行问题及修复记录

在本地环境配置并尝试运行 `python3 mscan.py` 时，暴露了以下问题，现已全部修复：

## 1. 缺少全局级别的 Python 核心依赖
* **问题描述**：启动时报 `ModuleNotFoundError: No module named 'requests'`
* **解决方案**：在项目的 `venv` 虚拟环境中安装依赖。
  ```bash
  source venv/bin/activate
  pip install requests
  ```

## 2. 三方插件模块的代码库组件缺失
* **问题描述**：运行如 `saucerframe` 模块时，抛出 `ModuleNotFoundError: No module named 'gevent'`。由于 MScan 包含多个三方子项目，它们并没有在根目录统一管理依赖。
* **解决方案**：进入各个三方模块目录，利用它们各自的依赖清单文件全量安装。
  ```bash
  pip install -r web/saucerframe/requirement.txt
  pip install -r web/POC-bomber/requirements.txt
  ```

## 3. Bin 目录下的可执行文件缺乏执行权限
* **问题描述**：扫描过程中抛出如 `/bin/sh: 行 1: bin/./amass: 权限不够`。源码中的二进制文件（如 `amass`, `httpx`, `afrog`, `nuclei`）没有默认的 Linux 执行权限。
* **解决方案**：赋予 `bin/` 目录下所有的二进制文件执行权限。
  ```bash
  chmod +x bin/*
  ```

## 4. 缺少必要的数据输出缓存目录
* **问题描述**：工具在运行探测工作时，尝试写入结果文件失败，报出类似 `Failed to open the text output file: open data/amass/domain.txt: no such file or directory`。这是因为 `data/` 下部分输出文件夹没有配置被自动创建。
* **解决方案**：手动建立缺失的相关依赖日志文件夹。
  ```bash
  mkdir -p data/amass data/afrog data/xray
  ```

## 5. 前置测试为空时诱发的业务流异常强退
* **问题描述**：在进行诸如 `reads('data/fuzz/data.json')` 解析时，如果前置流程并未生成该文件（例如没有检出存活域名，所以没触发该模块），由于代码未使用异常捕获结构，会导致产生 `FileNotFoundError` 并中断整个扫描检测流。
* **解决方案**：对项目核心的文本读取函数 `reads(data)` 添加了增强校验，当遇到不存在的文件时予以静默返回。并在 `mscan.py` 中做了如下修改：
  ```python
  def reads(data):
      if not os.path.exists(data):
          return []
      with open(data, 'r', encoding='utf-8') as f:
          text = f.readlines()
      return text
  ```

## 6. Amass 获取不到子域名时导致后续流程被跳过
* **问题描述**：原版代码中，如果 `amass` 被动扫描找不到子域名，会导致生成的 `data/amass/domain.txt` 为空，这直接导致后续的 `httpx` 存活检测以及各类漏扫模块（如 POC-bomber、saucerframe）拿不到任何输入（显示 "No targets found"），此时连原本用户写入的测试根域名也会被丢弃漏扫。
* **解决方案**：在 `mscan.py` 这个文件中的 `amass()` 阶段，让代码合并原始用户输入的 `domain.txt` 到 `data/amass/domain.txt` 中，确保不管有没有扫出子域名，源域名都始终会进入后续的 pipeline 等待扫描：
  ```python
  def amass():
      run_popen('bin/./amass enum -passive -df domain.txt -config config/amass.ini -o data/amass/domain.txt')
      domains = set()
      for line in reads('domain.txt'):
          if line.strip():
              domains.add(line.strip())
      for line in reads('data/amass/domain.txt'):
          if line.strip():
              domains.add(line.strip())
      with open('data/amass/domain.txt', 'w', encoding='utf-8') as f:
          for d in domains:
              f.write(d + '\n')
  ```
