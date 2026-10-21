import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const [baseline, results, revision, commandsPath] = process.argv.slice(2);
if (!commandsPath) throw Error('usage: node benches/selector_manifest.mjs BASELINE_WORKTREE RESULTS_DIRECTORY CANDIDATE_REVISION COMMANDS_JSON');
const commands = JSON.parse(fs.readFileSync(commandsPath, 'utf8'));
for (const name of ['baseline_build', 'candidate_build', 'profile', 'run', 'aggregate']) {
  if (typeof commands[name] !== 'string' || !commands[name].trim()) throw Error(`missing command metadata: ${name}`);
}
const run = (cmd, args, cwd = process.cwd()) => execFileSync(cmd, args, { cwd, encoding: 'utf8' }).trim();
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const file = p => ({ bytes: fs.statSync(p).size, sha256: hash(fs.readFileSync(p)) });
const base = run('git', ['rev-parse', 'HEAD'], baseline);
const sources = run('git', ['diff', '--name-only', '--diff-filter=d', `${base}..${revision}`]).split('\n')
  .filter(p => /\.(rs|toml|lock|sh|mjs)$/.test(p));
sources.push('src/lib.rs');
const artifacts = {};
for (const name of ['old.log', 'new.log', 'old-selector', 'new-selector', 'selector_measurement.rs']) {
  artifacts[name] = file(path.join(results, name));
}
const helper = file('benches/selector_measurement.rs');
if (helper.sha256 !== artifacts['selector_measurement.rs'].sha256) throw Error('baseline helper changed');
if (file(path.join(baseline, 'benches/selector_measurement.rs')).sha256 !== helper.sha256) {
  throw Error('copy the measured helper into BASELINE_WORKTREE/benches/selector_measurement.rs');
}
const patch = execFileSync('git', ['diff', '--binary'], { cwd: baseline, encoding: 'utf8' });
if (!patch.includes('diff --git a/benches/selector_measurement.rs b/benches/selector_measurement.rs') ||
    !fs.readFileSync(path.join(baseline, 'src/client_proxy_selector.rs'), 'utf8')
      .includes('#[path = "../benches/selector_measurement.rs"]')) {
  throw Error('use a relative helper path and git add -N benches/selector_measurement.rs in the baseline');
}
console.log(JSON.stringify({
  baseline: {
    revision: base,
    patch,
    patch_sha256: hash(patch),
    lockfile: file(path.join(baseline, 'Cargo.lock')),
    patched_selector: file(path.join(baseline, 'src/client_proxy_selector.rs')),
    build: commands.baseline_build,
  },
  candidate: {
    revision: run('git', ['rev-parse', revision]),
    tree: run('git', ['rev-parse', `${revision}^{tree}`]),
    sources: Object.fromEntries([...new Set(sources)].map(p => {
      const bytes = execFileSync('git', ['show', `${revision}:${p}`]);
      if (hash(bytes) !== file(p).sha256) throw Error(`source differs from measured revision: ${p}`);
      return [p, { bytes: bytes.length, sha256: hash(bytes) }];
    })),
    build: commands.candidate_build,
  },
  rustc: run('rustc', ['-Vv']),
  cpu: run('lscpu', ['--json']),
  allocator: 'System (lib unit test; the server binary uses jemalloc)',
  profile: commands.profile,
  run: commands.run,
  aggregate: commands.aggregate,
  checks: 'All 4096 queries per process verified before timing; counted stub DNS asserts exactly one lookup per measured DNS route.',
  artifacts,
  tooling: Object.fromEntries(['benches/run_selector.sh', 'benches/compare_selector.mjs', 'benches/selector_manifest.mjs'].map(p => [p, file(p)])),
}, null, 2));
