"""Exercise the built CLI against an owned local server and real browser oracle."""
import html
import importlib.util
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

if not importlib.util.find_spec('playwright') or not importlib.util.find_spec('yaml'):
    print('optional Python/browser dependencies unavailable')
    raise SystemExit(77)
from playwright.sync_api import sync_playwright
try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        browser.close()
except Exception:
    print('optional Chromium runtime unavailable')
    raise SystemExit(77)

executable, scenario, scratch = sys.argv[1:]
root = Path(scratch)
pack = root / 'pack'
pack.mkdir()
requests = []
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append(self.path)
        parsed = urlsplit(self.path)
        if parsed.path == '/controlled':
            self.send_response(200 if self.headers.get('Authorization') == 'Bearer fixture-entitled' else 403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"fixture":"controlled"}')
            return
        value = parse_qs(parsed.query).get('q', [''])[0]
        body = value if parsed.path == '/vulnerable' else html.escape(value)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(f'<!doctype html><title>scan fixture</title>{body}'.encode())
    def log_message(self, *_args):
        pass
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()

probe = '''// @id: browser-proof
// @attach_scheme: path
// @vuln_class: xss
// @severity: high
// @requires_auth_count: 0
// @requires_capability: dom
async function cxgProbe(cxg) {
  const path = '/ENDPOINT?q=' + encodeURIComponent('<script>alert("scan-fixture")</script>');
  const observed = await cxg.page.probeXss(path, {marker: 'scan-fixture', settleMs: 0});
  return [{id: 'browser-proof', vuln_class: 'xss', severity: 'high',
    endpoint: cxg.url(path), confirmed: observed.executed,
    description: observed.executed ? 'execution observed' : 'no execution on escaped page',
    evidence: {outcome: observed.executed ? 'confirmed' : 'refuted', observed}}];
}
'''
probe = probe.replace('ENDPOINT', 'safe' if scenario == 'refuted' else 'vulnerable')
if scenario == 'refuted':
    # A refutation needs an engine-observed entitled control, rather than the
    # probe's own claim that a negative response proves a mitigation.
    probe = '''// @id: access-control
// @attach_scheme: path
// @vuln_class: idor
// @requires_auth_count: 2
// @requires_capability: http_raw
async function cxgProbe(cxg) {
  const attacker = await cxg.rawAs(0, '/controlled', {method: 'GET'});
  const entitled = await cxg.rawAs(1, '/controlled', {method: 'GET'});
  return [{id: 'access-control', vuln_class: 'idor', confirmed: false,
    endpoint: cxg.url('/controlled'), description: 'access denied with an entitled control',
    evidence: {outcome: 'refuted', status: attacker.status, benign_status: entitled.status}}];
}
'''
if scenario == 'missing':
    probe = probe.replace('@requires_auth_count: 0', '@requires_auth_count: 2\n// @requires_identities: {"victim":"missing-victim","attacker":"missing-attacker"}')
(pack / 'probe.js').write_text(probe)
if scenario in {'mixed', 'partial', 'duplicate_id', 'partial_duplicate'}:
    (pack / 'scanner.py').write_text('''# @id: ordinary-scanner
import json, os, urllib.request
response = urllib.request.urlopen('http://' + os.environ['CERT_X_GEN_TARGET_HOST'] + ':' + os.environ['CERT_X_GEN_TARGET_PORT'] + '/scanner').read()
print(json.dumps([{'title': 'scanner observation', 'severity': 'low', 'description': 'scanner template output', 'evidence': {'body': response.decode()}}]))
''')
if scenario in {'partial', 'partial_duplicate'}:
    required = probe if scenario == 'partial_duplicate' else probe.replace('@id: browser-proof', '@id: identity-proof')
    (pack / 'requires-identities.js').write_text(required.replace('@requires_auth_count: 0', '@requires_auth_count: 2'))
if scenario == 'duplicate_id':
    scanner = pack / 'scanner.py'
    scanner.write_text(scanner.read_text().replace('@id: ordinary-scanner', '@id: browser-proof'))
# Poison model CLIs and the scanner's Node launcher. Browser-driver Node uses its
# own absolute executable; a probe must never reach the scanner's Node path.
tripwire = root / 'forbidden.log'
bin_dir = root / 'bin'
bin_dir.mkdir()
for tool in ['claude', 'codex', 'gemini', 'crush', 'node']:
    path = bin_dir / tool
    path.write_text('#!/bin/sh\nprintf "%s\\n" "$0" >> ' + shlex.quote(str(tripwire)) + '\nexit 88\n')
    path.chmod(0o755)
env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
           CERT_X_GEN_HOME=str(root / 'home'), CXG_NO_BANNER='1', CXG_PYTHON=sys.executable,
           CXG_CODEGRAPH_MCP=str(root / 'missing-codegraph'))
env.pop('CXG_SOURCE', None)
env.pop('ANTHROPIC_API_KEY', None)
env.pop('OPENAI_API_KEY', None)
try:
    command = [executable, '--disable-update-check', 'scan', '--no-author', '--scope', f'http://127.0.0.1:{server.server_port}',
        '--template-dir', str(pack), '--session-dir', str(root / 'sessions'), '--output', str(root / 'combined')]
    if scenario == 'refuted':
        state = root / 'state.json'
        state.write_text('{"cookies":[],"origins":[]}')
        for name, tier in [('attacker', 'low'), ('entitled', 'high')]:
            imported = subprocess.run([executable, 'pentest', 'auth', 'import', '--profile', name,
                '--target', f'http://127.0.0.1:{server.server_port}', '--storage-state', str(state),
                '--auth-dir', str(root / 'auth'), '--tier', tier,
                '--header', f'Authorization:Bearer fixture-{name}'],
                cwd=root, env=env, capture_output=True, text=True, timeout=20)
            assert imported.returncode == 0, imported.stderr
        command += ['--auth', 'attacker,entitled', '--auth-dir', str(root / 'auth')]
    if scenario == 'direct':
        command[command.index('--template-dir')] = '--templates'
        command[command.index(str(pack))] = str(pack / 'probe.js')
    if os.environ.get('CXG_TEST_FAIL_ON'):
        command += ['--fail-on', os.environ['CXG_TEST_FAIL_ON']]
    out = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=80)
    print(out.stdout)
    print(out.stderr, file=sys.stderr)
    report = json.loads((root / 'combined.json').read_text())
    engine = report['probe_results']
    assert engine['authoring']['mode'] == 'no_author'
    assert engine['authoring']['model_calls'] == 0
    assert not tripwire.exists(), tripwire.read_text() if tripwire.exists() else ''
    if scenario in {'missing', 'partial', 'partial_duplicate'}:
        assert out.returncode == 4, out.returncode
        assert engine['refused_probes']
        assert 'requires 2 captured authenticated identities' in json.dumps(engine['refused_probes'])
        if scenario == 'partial_duplicate':
            assert any(r.get('path') == str(pack / 'requires-identities.js') for r in engine['refused_probes'])
            assert {'confirmed', 'skipped'} <= {e['status'] for e in report['executions'] if e['template_id'] == 'browser-proof'}
        if scenario == 'missing':
            assert not requests, requests
            assert not report['findings']
    elif scenario == 'refuted':
        assert out.returncode == (2 if os.environ.get('CXG_TEST_FAIL_ON') == 'refuted' else 0), out.returncode
        assert not report['findings']
        assert engine['sessions'][0]['report']['mitigation_verifications']
    else:
        assert out.returncode == 2, out.returncode
    if scenario != 'missing':
        assert any(path.startswith('/controlled' if scenario == 'refuted' else '/vulnerable?') for path in requests), requests
        native = engine['sessions'][0]
        assert Path(native['audit_log']).is_file()
        assert Path(native['report_path']).is_file()
        assert native['report']['authoring']['model_calls'] == 0
        rows = [json.loads(line) for line in Path(native['audit_log']).read_text().splitlines()]
        audited = sum(r.get('_event') == 'request' and r.get('url', '').startswith(('http://', 'https://')) for r in rows)
        assert native['request_counts']['audited_http_attempts'] == audited
        assert report['statistics']['network_requests_measured'] >= audited
        assert report['statistics']['network_requests'] is None
        if os.environ.get('CXG_EXPECT_FULL_AUDIT'):
            scanner_requests = 1 if scenario in {'mixed', 'partial', 'duplicate_id', 'partial_duplicate'} else 0
            assert audited == len(requests) - scanner_requests, (audited, requests)
    assert report['executions'], 'probe executions must be available to status gates'
    if scenario == 'refuted':
        assert report['executions'][0]['status'] == 'refuted'
    if scenario not in {'missing', 'refuted'}:
        assert any(e['status'] == 'confirmed' and 'engine-adjudicated' in (e['detail'] or '') for e in report['executions'])
        assert any(f['verdict_source'] == 'engine-adjudicated' for f in report['findings'])
    if scenario in {'mixed', 'partial', 'duplicate_id', 'partial_duplicate'}:
        assert '/scanner' in requests
        assert any(f['verdict_source'] == 'template-reported' for f in report['findings'])
    if scenario == 'missing':
        for index, prefix in enumerate([['scan', '--pentest'], ['pentest', 'run']]):
            native_path = root / f'legacy-{index}.json'
            replay = subprocess.run([executable, *prefix, '--codebase', str(root),
                '--target', f'http://127.0.0.1:{server.server_port}', '--template-dir', str(pack),
                '--no-author', '--session-dir', str(root / f'legacy-session-{index}'),
                '--output', str(native_path)], cwd=root, env=env, capture_output=True, text=True, timeout=80)
            assert replay.returncode == 4, (prefix, replay.returncode, replay.stdout, replay.stderr)
            native_report = json.loads(native_path.read_text())
            assert native_report['auth_skipped'][0]['missing_roles']
            assert not native_report['mitigation_verifications']
        assert not tripwire.exists()
    print('PASS', scenario, 'requests', len(requests), 'model calls 0')
finally:
    server.shutdown()
    server.server_close()
    thread.join()
