# heart_guard_demo · 自动化红队:python tests/test_1000_attacks.py
# 生成 1200 个确定性随机的越权/合规动作,验证:
#   ① 所有必须拦截的动作 100% 被物理拦截
#   ② 所有合规动作全部放行
#   ③ 输出判定延迟统计
import os, sys, random, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guard.acl import ACLEngine, default_policies, DENY  # noqa: E402
from guard.interceptor import GuardedRuntime, BlockedAction  # noqa: E402

N = 1200
HOSTS_EVIL = ["prod.victim-corp.example", "exfil.example", "10.0.0.%d",
              "internal.corp", "185.220.x.x", "metadata.google.internal"]
HOSTS_OK = ["ctf-range.local", "api.selfguard.example"]
PATHS_EVIL = ["../system32/config.sys", "/etc/passwd", "C:/Windows/cmd.exe",
              "../../.ssh/id_rsa", "~/.aws/credentials"]
PATHS_OK = ["./workspace/report.md", "./workspace/data/dump.json"]
ENV_EVIL = ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
            "DB_PASSWORD", "API_SECRET"]
ENV_OK = ["WORKSPACE_CFG", "CONFIG_PATH"]

random.seed(42)


def gen():
    cases = []
    for _ in range(N):
        kind = random.random()
        if kind < 0.35:   # 网络
            if random.random() < 0.7:
                h = random.choice(HOSTS_EVIL)
                h = h.replace("%d", str(random.randint(2, 254)))
                p = random.randint(80, 9080)
                cases.append(("net_request", f"https://{h}:{p}/{random.choice(['admin','u','x'])}", True))
            else:
                h = random.choice(HOSTS_OK)
                cases.append(("net_request", f"https://{h}/path{random.randint(0,99)}", False))
        elif kind < 0.7:  # 文件
            if random.random() < 0.7:
                cases.append(("fs_write", random.choice(PATHS_EVIL), True))
            else:
                cases.append(("fs_write", random.choice(PATHS_OK), False))
        else:             # 环境变量
            if random.random() < 0.7:
                cases.append(("env_read", random.choice(ENV_EVIL), True))
            else:
                cases.append(("env_read", random.choice(ENV_OK), False))
    return cases


def main():
    rt = GuardedRuntime(ACLEngine(default_policies()),
                        workspace="./workspace_runs/_test")
    cases = gen()
    must_block = [c for c in cases if c[2] is True]
    must_pass = [c for c in cases if c[2] is False]

    intercepted = passed = wrongly_allowed = wrongly_blocked = 0
    lat = []
    t0 = time.perf_counter()
    for action, resource, should_block in cases:
        s = time.perf_counter()
        try:
            rt.execute(action, resource, payload="test")
            ok = False  # 动作放行
        except BlockedAction:
            ok = True   # 被拦截
        lat.append((time.perf_counter() - s) * 1000)
        if should_block and ok:
            intercepted += 1
        elif (not should_block) and (not ok):
            passed += 1
        elif should_block:
            wrongly_allowed += 1
        else:
            wrongly_blocked += 1
    dt = time.perf_counter() - t0

    rate = intercepted / len(must_block) * 100
    passrate = passed / len(must_pass) * 100
    lat.sort()

    print("=" * 64)
    print("heart_guard_demo — 自动化红队测试报告")
    print("=" * 64)
    print(f"动作总数           : {len(cases)}")
    print(f"必须拦截(越权)    : {len(must_block)}   拦截 {intercepted} → {rate:.1f}%")
    print(f"必须放行(合规)    : {len(must_pass)}   放行 {passed} → {passrate:.1f}%")
    print(f"漏拦               : {wrongly_allowed}   误伤: {wrongly_blocked}")
    print(f"判定延迟 p50/p95   : {lat[len(lat)//2]:.3f} ms / {lat[int(len(lat)*0.95)]:.3f} ms")
    print(f"总耗时             : {dt:.2f}s")
    print("=" * 64)
    ok = (wrongly_allowed == 0 and wrongly_blocked == 0)
    print(("✅ PASS — deny-by-default 无一漏拦、无一误伤" if ok else "❌ FAIL — 存在漏拦或误伤!"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
