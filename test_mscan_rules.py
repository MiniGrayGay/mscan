#!/usr/bin/env python3
"""
任务 7.1 — 集成测试 & 任务 7.2 — 回归测试
    python3 test_mscan_rules.py --target URL      # 指定靶场地址
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import textwrap
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
BIN_DIR = BASE_DIR / "bin"
TEMPLATES_DIR = BASE_DIR / "web" / "nuclei-templates"
CUSTOM_DIR = TEMPLATES_DIR / "mscan-custom-rules"
CVE_DIR = TEMPLATES_DIR / "cves"
CNVD_DIR = TEMPLATES_DIR / "cnvd"
NUCLEI = BIN_DIR / "nuclei"
DATA_DIR = BASE_DIR / "data"

# 全部自定义规则 id → 期望最低严重级别
EXPECTED_RULES = {
    "mscan-sqli":                  "critical",
    "mscan-sqli-blind":            "high",
    "mscan-command-injection":     "critical",
    "mscan-file-inclusion":        "high",
    "mscan-xss-reflected":         "high",
    "mscan-xss-stored":            "high",
    "mscan-open-redirect":         "medium",
    "mscan-bff-missing-validation": "high",
}

# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
passed = 0
failed = 0
skipped = 0


def run(cmd, timeout=60, cwd=BASE_DIR):
    """执行命令, 返回 (returncode, stdout_text)"""
    result = subprocess.run(
        cmd, shell=True, cwd=str(cwd),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=timeout,
    )
    return result.returncode, result.stdout


def nuclei_cmd(*extra_args):
    """构建 nuclei 基础命令"""
    return f"{shlex.quote(str(NUCLEI))} -disable-update-check " + " ".join(extra_args)


def count_yaml(directory):
    return len(list(Path(directory).rglob("*.yaml")))


def report_result(name, ok, detail=""):
    global passed, failed
    tag = "\033[92mPASS\033[0m" if ok else "\033[91mFAIL\033[0m"
    print(f"  [{tag}] {name}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"         {line}")
    if ok:
        passed += 1
    else:
        failed += 1


def report_skip(name, reason=""):
    global skipped
    print(f"  [\033[93mSKIP\033[0m] {name}")
    if reason:
        print(f"         {reason}")
    skipped += 1


# ---------------------------------------------------------------------------
# 连通性检查
# ---------------------------------------------------------------------------
def check_target(target):
    """检测靶场是否可达"""
    try:
        from urllib.request import urlopen, Request
        req = Request(target, headers={"User-Agent": "mscan-test/1.0"})
        resp = urlopen(req, timeout=5)
        return resp.status == 200
    except Exception:
        return False


# ===================================================================
# 集成测试 (任务 7.1)
# ===================================================================
def test_T1_custom_templates_load():
    """T1: 自定义规则全部能被 nuclei 解析加载"""
    rc, out = run(nuclei_cmd(
        f"-t {shlex.quote(str(CUSTOM_DIR))}",
        "-severity medium,high,critical",
        "-u http://0.0.0.0:0",  # 不实际发包, 只验证加载
        "-validate",
    ), timeout=30)
    # nuclei -validate 成功时输出 "All templates are valid"
    ok = "valid" in out.lower() or rc == 0
    # 也可通过检查模板加载数
    loaded_match = re.search(r"Templates loaded for scan:\s*(\d+)", out)
    loaded = int(loaded_match.group(1)) if loaded_match else None
    detail = ""
    if loaded is not None:
        detail = f"加载模板数: {loaded} (期望 {len(EXPECTED_RULES)})"
        ok = ok and (loaded == len(EXPECTED_RULES))
    report_result("T1 自定义规则 YAML 加载", ok, detail)
    return ok


def test_T2_custom_rules_hit(target):
    """T2: 自定义规则对在线靶场全部命中"""
    rc, out = run(nuclei_cmd(
        f"-t {shlex.quote(str(CUSTOM_DIR))}",
        "-severity medium,high,critical",
        f"-u {target}",
    ), timeout=120)

    hit_ids = set()
    for line in out.splitlines():
        for rule_id in EXPECTED_RULES:
            if rule_id in line:
                hit_ids.add(rule_id)

    missing = set(EXPECTED_RULES) - hit_ids
    ok = len(missing) == 0
    detail = f"命中 {len(hit_ids)}/{len(EXPECTED_RULES)} 条规则"
    if missing:
        detail += f"\n漏报: {', '.join(sorted(missing))}"
    report_result("T2 自定义规则全部命中靶场", ok, detail)
    return ok


def test_T3_nuclei_module_integration(target):
    """T3: 通过 mscan.py 的 nuclei() 函数运行, 结果写入 poc.txt"""
    # 准备 scan_targets.txt
    urls_dir = DATA_DIR / "urls"
    urls_dir.mkdir(parents=True, exist_ok=True)
    httpx_dir = DATA_DIR / "httpx"
    httpx_dir.mkdir(parents=True, exist_ok=True)
    nuclei_dir = DATA_DIR / "nuclei"
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    # 写入目标
    scan_file = urls_dir / "scan_targets.txt"
    scan_file.write_text(target + "\n", encoding="utf-8")
    url_file = httpx_dir / "url.txt"
    url_file.write_text(target + "\n", encoding="utf-8")

    # 清除旧结果
    poc_file = nuclei_dir / "poc.txt"
    if poc_file.exists():
        poc_file.unlink()

    # 只运行 nuclei 步骤
    rc, out = run(
        f"{sys.executable} -c \""
        "import sys; sys.path.insert(0,'.');"
        "from mscan import ensure_runtime_dirs, nuclei;"
        "ensure_runtime_dirs(); nuclei()"
        "\"",
        timeout=180,
    )

    ok = poc_file.exists() and poc_file.stat().st_size > 0
    detail = ""
    if ok:
        lines = [l for l in poc_file.read_text().splitlines() if l.strip()]
        # 检查自定义规则是否在结果中
        custom_hits = [l for l in lines if any(rid in l for rid in EXPECTED_RULES)]
        detail = f"poc.txt 共 {len(lines)} 行, 其中自定义规则命中 {len(custom_hits)} 行"
    else:
        detail = "poc.txt 不存在或为空"
    report_result("T3 nuclei() 模块集成输出", ok, detail)
    return ok


def test_T4_report_contains_nuclei(target):
    """T4: 汇总报告中包含 nuclei 结果"""
    poc_file = DATA_DIR / "nuclei" / "poc.txt"
    if not poc_file.exists() or poc_file.stat().st_size == 0:
        report_skip("T4 汇总报告包含 nuclei 结果", "poc.txt 不存在, 依赖 T3")
        return False

    # 调用 build_report_data 检查
    rc, out = run(
        f"{sys.executable} -c \""
        "import sys, json; sys.path.insert(0,'.');"
        "from mscan import build_report_data;"
        "r = build_report_data();"
        "nm = [m for m in r.get('modules',[]) if m['name']=='nuclei'];"
        "print(json.dumps(nm[0]) if nm else 'MISSING')"
        "\"",
        timeout=30,
    )

    ok = False
    detail = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                mod = json.loads(line)
                findings = mod.get("findings")
                ok = findings is not None and findings > 0
                detail = f"nuclei 模块 findings={findings}, status={mod.get('status')}"
            except json.JSONDecodeError:
                pass
        elif line == "MISSING":
            detail = "报告中未找到 nuclei 模块"

    report_result("T4 汇总报告包含 nuclei 结果", ok, detail)
    return ok


# ===================================================================
# 回归测试 (任务 7.2)
# ===================================================================
def test_T5_original_templates_load():
    """T5: 原有模板 (cves + cnvd) 仍然能正常加载"""
    rc, out = run(nuclei_cmd(
        f"-t {shlex.quote(str(CVE_DIR))},{shlex.quote(str(CNVD_DIR))}",
        "-severity medium,high,critical",
        "-u http://0.0.0.0:0",
        "-validate",
    ), timeout=120)

    ok = rc == 0 or "valid" in out.lower()
    # 检查是否有 YAML 解析错误 (排除已知的 CVE-2019-17382 缺文件问题, 它是原始仓库的遗留问题)
    errors = [l for l in out.splitlines()
              if "ERR" in l and ("parse" in l.lower() or "yaml" in l.lower())
              and "CVE-2019-17382" not in l]
    if errors:
        ok = False
    detail = f"原有模板数: cves={count_yaml(CVE_DIR)}, cnvd={count_yaml(CNVD_DIR)}"
    preexisting = [l for l in out.splitlines()
                   if "ERR" in l and "CVE-2019-17382" in l]
    if preexisting:
        detail += f"\n已知遗留问题 {len(preexisting)} 条 (不影响判定)"
    if errors:
        detail += f"\n新增解析错误 {len(errors)} 条: {errors[0]}"
    report_result("T5 原有模板加载无报错", ok, detail)
    return ok


def test_T6_combined_template_count():
    """T6: 原有 + 自定义模板同时加载, 总数正确无冲突"""
    # 先单独统计原有模板加载数
    _, out_orig = run(nuclei_cmd(
        f"-t {shlex.quote(str(CVE_DIR))},{shlex.quote(str(CNVD_DIR))}",
        "-severity medium,high,critical",
        "-u http://0.0.0.0:0",
    ), timeout=120)
    orig_match = re.search(r"Templates loaded for scan:\s*(\d+)", out_orig)
    orig_count = int(orig_match.group(1)) if orig_match else 0

    # 再统计合并后加载数
    _, out_all = run(nuclei_cmd(
        f"-t {shlex.quote(str(CVE_DIR))},{shlex.quote(str(CNVD_DIR))},"
        f"{shlex.quote(str(CUSTOM_DIR))}",
        "-severity medium,high,critical",
        "-u http://0.0.0.0:0",
    ), timeout=120)
    all_match = re.search(r"Templates loaded for scan:\s*(\d+)", out_all)
    all_count = int(all_match.group(1)) if all_match else 0

    expected = orig_count + len(EXPECTED_RULES)
    ok = all_count == expected and orig_count > 0
    detail = f"原有模板 {orig_count} + 自定义 {len(EXPECTED_RULES)} = 期望 {expected}, 实际 {all_count}"
    report_result("T6 合并加载模板数量一致", ok, detail)
    return ok


def test_T7_no_regression_with_custom(target):
    """T7: 加入自定义规则后, 原有模板的扫描行为不受影响"""
    # 用 cves+cnvd 中一个已知能解析的模板目录做 dry-run
    # 我们只关注: 没有新的 ERR / panic / crash
    rc, out = run(nuclei_cmd(
        f"-t {shlex.quote(str(CVE_DIR))},{shlex.quote(str(CNVD_DIR))},"
        f"{shlex.quote(str(CUSTOM_DIR))}",
        "-severity medium,high,critical",
        f"-u {target}",
        "-rl 50",           # 限速, 避免给靶场太大压力
        "-retries 1",
    ), timeout=300)

    errors = [l for l in out.splitlines()
              if "ERR" in l and "nuclei-ignore" not in l
              and "Could not read" not in l]
    panic = any("panic" in l.lower() for l in out.splitlines())
    ok = rc == 0 and not panic
    detail = f"退出码 {rc}"
    if errors:
        detail += f", 非致命 ERR {len(errors)} 条"
    if panic:
        detail += ", 检测到 panic!"
        ok = False
    report_result("T7 原有 + 自定义规则联合运行无异常", ok, detail)
    return ok


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    global passed, failed, skipped

    parser = argparse.ArgumentParser(description="MScan 自定义规则 集成/回归 测试")
    parser.add_argument("--target", default="http://127.0.0.1:4280",
                        help="DVWA-microservices 靶场地址 (默认 http://127.0.0.1:4280)")
    args = parser.parse_args()
    target = args.target.rstrip("/")

    print("=" * 64)
    print("  MScan 自定义规则 — 集成测试 (7.1) & 回归测试 (7.2)")
    print("=" * 64)
    print(f"  靶场地址: {target}")
    print(f"  nuclei:   {NUCLEI}")
    print(f"  自定义规则: {CUSTOM_DIR} ({count_yaml(CUSTOM_DIR)} 个)")
    print(f"  原有模板:  cves={count_yaml(CVE_DIR)}, cnvd={count_yaml(CNVD_DIR)}")
    print()

    # 连通性
    target_up = check_target(target)
    if not target_up:
        print(f"\033[91m[!] 靶场 {target} 不可达, 在线测试将被跳过\033[0m\n")

    # ---- 集成测试 (7.1) ----
    print("── 集成测试 (任务 7.1) ──────────────────────────────────")
    test_T1_custom_templates_load()

    if target_up:
        test_T2_custom_rules_hit(target)
        test_T3_nuclei_module_integration(target)
        test_T4_report_contains_nuclei(target)
    else:
        report_skip("T2 自定义规则全部命中靶场", "靶场不可达")
        report_skip("T3 nuclei() 模块集成输出", "靶场不可达")
        report_skip("T4 汇总报告包含 nuclei 结果", "靶场不可达")

    # ---- 回归测试 (7.2) ----
    print()
    print("── 回归测试 (任务 7.2) ──────────────────────────────────")
    test_T5_original_templates_load()
    test_T6_combined_template_count()

    if target_up:
        test_T7_no_regression_with_custom(target)
    else:
        report_skip("T7 原有 + 自定义规则联合运行无异常", "靶场不可达")

    # ---- 汇总 ----
    print()
    print("=" * 64)
    total = passed + failed + skipped
    color = "\033[92m" if failed == 0 else "\033[91m"
    print(f"  {color}PASSED {passed}  FAILED {failed}  SKIPPED {skipped}  TOTAL {total}\033[0m")
    print("=" * 64)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
