import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

test('manifest records supplied commands and embeds a portable baseline helper', t => {
  const scratch = path.join(os.homedir(), 'tmp');
  fs.mkdirSync(scratch, { recursive: true });
  const root = fs.mkdtempSync(path.join(scratch, 'selector-manifest-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const baseline = path.join(root, 'baseline');
  const candidate = path.join(root, 'candidate');
  const results = path.join(root, 'results');
  const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  const write = (dir, file, content) => {
    const target = path.join(dir, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  };
  write(baseline, 'src/lib.rs', '// fixture\n');
  write(baseline, 'src/removed.rs', '// removed in the candidate\n');
  write(baseline, 'src/client_proxy_selector.rs', '// selector\n');
  write(baseline, 'Cargo.lock', '# fixture\n');
  git(baseline, 'init', '-q');
  git(baseline, 'add', '.');
  const commit = cwd => git(cwd, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture');
  commit(baseline);
  git(root, 'clone', '-q', baseline, candidate);
  git(candidate, 'rm', 'src/removed.rs');
  const helper = '// measured helper\n';
  write(candidate, 'benches/selector_measurement.rs', helper);
  for (const file of ['run_selector.sh', 'compare_selector.mjs', 'selector_manifest.mjs']) {
    write(candidate, `benches/${file}`, '// fixture tool\n');
  }
  git(candidate, 'add', '.');
  commit(candidate);
  write(baseline, 'benches/selector_measurement.rs', helper);
  write(baseline, 'src/client_proxy_selector.rs', '#[path = "../benches/selector_measurement.rs"]\nmod measurement_bench;\n');
  git(baseline, 'add', '-N', 'benches/selector_measurement.rs');
  for (const file of ['old.log', 'new.log', 'old-selector', 'new-selector', 'selector_measurement.rs']) {
    write(results, file, file.endsWith('.rs') ? helper : 'fixture artifact\n');
  }
  const commands = {
    baseline_build: 'baseline build from test', candidate_build: 'candidate build from test',
    profile: 'explicit test profile', run: 'explicit test run', aggregate: 'explicit aggregation',
  };
  write(root, 'commands.json', JSON.stringify(commands));
  const script = fileURLToPath(new URL('./selector_manifest.mjs', import.meta.url));
  const invoke = () => spawnSync(process.execPath, [script,
    baseline, results, 'HEAD', path.join(root, 'commands.json')], { cwd: candidate, encoding: 'utf8' });
  const result = invoke();
  assert.equal(result.status, 0, result.stderr);
  const manifest = JSON.parse(result.stdout);
  assert.ok(!Object.hasOwn(manifest.candidate.sources, 'src/removed.rs'));
  assert.equal(manifest.baseline.build, commands.baseline_build);
  assert.equal(manifest.candidate.build, commands.candidate_build);
  assert.equal(manifest.profile, commands.profile);
  assert.equal(manifest.run, commands.run);
  assert.equal(manifest.aggregate, commands.aggregate);
  assert.match(manifest.baseline.patch, /\+\/\/ measured helper/);
  assert.ok(!manifest.baseline.patch.includes(root));
  const reproduction = path.join(root, 'reproduction');
  git(root, 'clone', '-q', baseline, reproduction);
  const applyOptions = { cwd: reproduction, input: manifest.baseline.patch, encoding: 'utf8' };
  execFileSync('git', ['apply', '--check', '-'], applyOptions);
  execFileSync('git', ['apply', '-'], applyOptions);
  assert.equal(fs.readFileSync(path.join(reproduction, 'benches/selector_measurement.rs'), 'utf8'), helper);
  assert.equal(fs.readFileSync(path.join(reproduction, 'src/client_proxy_selector.rs'), 'utf8'),
    fs.readFileSync(path.join(baseline, 'src/client_proxy_selector.rs'), 'utf8'));
  git(baseline, 'reset', '-q', '--', 'benches/selector_measurement.rs');
  const missingPatch = invoke();
  assert.notEqual(missingPatch.status, 0);
  assert.match(missingPatch.stderr, /git add -N/);
  write(root, 'commands.json', '{}');
  const missingCommands = invoke();
  assert.notEqual(missingCommands.status, 0);
  assert.match(missingCommands.stderr, /missing command metadata/);
});
