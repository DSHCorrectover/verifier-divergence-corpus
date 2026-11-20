#!/usr/bin/env python3
"""ten-vendors-check.py — 10 大厂 agent tool-approval 语义断言矩阵（2026-11-20）
进攻线 = fail-open 模式在位断言；正面基准 = fail-closed 模式在位断言。
每项 PASS = 该厂商公开证据锚仍然成立（行级/机制级）。
run: GH_TOKEN=<pat> python3 ten-vendors-check.py   （或先 python3 -c "import ten_vendors_env"）"""
import os, sys, json, base64
import urllib.request as ur
TOK = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or ''
H = {'Authorization': f'Bearer {TOK}', 'User-Agent': 'ten-vendors-check'} if TOK else {'User-Agent': 'pub'}
def raw(repo, p):
    try:
        b = json.load(ur.urlopen(ur.Request(f'https://api.github.com/repos/{repo}/contents/{p}?ref=main', headers=H), timeout=15))
        return base64.b64decode(b['content']).decode(errors='replace')
    except Exception:
        return None
V = [
 ('gemini-cli #30369','offensive','google-gemini/gemini-cli',['packages/core/src/tools/mcp-client-manager.ts'],
  lambda f: bool(f[0]) and 'includeTools = override.includeTools ?? base.includeTools' in f[0]),
 ('openai-agents #6094','offensive','openai/openai-agents-python',['src/agents/mcp/server.py'],
  lambda f: bool(f[0]) and 'bool(policy.get(tool.name, False))' in f[0]),
 ('QwenLM qwen-code (vendor-confirmed P1)','offensive','QwenLM/qwen-code',['packages/core/src/tools/mcp-client-manager.ts'],
  lambda f: bool(f[0]) and 'includeTools' in f[0]),
 ('amazon-q','offensive','aws/amazon-q-developer-cli',['crates/chat-cli/src/util/tool_permission_checker.rs'],
  lambda f: bool(f[0]) and 'is_tool_in_allowlist' in f[0]),
 ('autogen #8498','offensive','microsoft/autogen',['python/packages/autogen-ext/src/autogen_ext/agents/openai/_openai_agent.py'],
  lambda f: bool(f[0]) and 'self._tools.append(cast(dict[str, Any], tool))' in f[0] and '{"type": "local_shell"}' in f[0]),
 ('deer-flow #8431','offensive','bytedance/deer-flow',['backend/packages/harness/deerflow/agents/lead_agent/agent.py','backend/packages/harness/deerflow/config/hitl_approval_config.py'],
  lambda f: bool(f[0]) and 'hitl_config.enabled is not True' in f[0] and bool(f[1]) and 'default=False' in f[1]),
 ('semantic-kernel (positive baseline)','baseline','microsoft/semantic-kernel',['python/semantic_kernel/agents/azure_ai/agent_thread_actions.py'],
  lambda f: bool(f[0]) and 'mcp_tool_approval_callback' in f[0] and 'was configured' in f[0] and 'return False' in f[0]),
 ('codex CLI (positive baseline)','baseline','openai/codex',['codex-rs/core/src/tools/approvals.rs'],
  lambda f: bool(f[0]) and 'request_mcp_tool_user_approval' in f[0]),
 ('claude-code sec-default (positive baseline)','baseline','anthropics/claude-code',['mods/sec-default/README.md'],
  lambda f: bool(f[0]) and 'fail closed' in f[0].lower()),
 ('llama-stack (positive baseline)','baseline','meta-llama/llama-stack',['src/ogx/providers/utils/tools/mcp.py'],
  lambda f: bool(f[0]) and 'non-pinned hosts are not allowed' in f[0]),
]
if __name__ == '__main__':
    R = []
    for name, tag, repo, files, ok in V:
        srcs = [raw(repo, p) for p in files]
        try: okv = bool(ok(srcs))
        except Exception: okv = False
        R.append({'vendor': name, 'type': tag, 'repo': repo, 'assert_ok': okv, 'check_files': files})
        print(('PASS' if okv else 'FAIL'), f'[{tag}]', name); sys.stdout.flush()
    p = sum(1 for r in R if r['assert_ok'])
    out = {'ts': __import__('time').strftime('%Y-%m-%dT%H:%M%z'), 'pass': p, 'total': len(R), 'rows': R}
    json.dump(out, open('ten-vendors-latest.json', 'w'), indent=1)
    print(f'===== TEN-VENDORS: {p}/{len(R)} PASS =====')
    sys.exit(0 if p == len(R) else 1)
