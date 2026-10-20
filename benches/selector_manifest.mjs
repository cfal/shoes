import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const [baseline, results, revision] = process.argv.slice(2);
if (!baseline || !results || !revision) throw Error('usage: node benches/selector_manifest.mjs BASELINE_WORKTREE RESULTS_DIRECTORY CANDIDATE_REVISION');
const run = (cmd, args, cwd = process.cwd()) => execFileSync(cmd, args, { cwd, encoding: 'utf8' }).trim();
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const file = p => ({ bytes: fs.statSync(p).size, sha256: hash(fs.readFileSync(p)) });
const base = run('git', ['rev-parse', 'HEAD'], baseline);
const sources = run('git', ['diff', '--name-only', `${base}..${revision}`]).split('\n')
  .filter(p => /\.(rs|toml|lock|sh|mjs)$/.test(p));
sources.push('src/lib.rs');
const artifacts = {};
for (const name of ['old.log', 'new.log', 'old-selector', 'new-selector', 'selector_measurement.rs']) {
  artifacts[name] = file(path.join(results, name));
}
const helper = file('benches/selector_measurement.rs');
if (helper.sha256 !== artifacts['selector_measurement.rs'].sha256) throw Error('baseline helper changed');
const patch = run('git', ['diff', '--binary'], baseline);
console.log(JSON.stringify({
  baseline: {
    revision: base,
    patch,
    patch_sha256: hash(patch),
    lockfile: file(path.join(baseline, 'Cargo.lock')),
    patched_selector: file(path.join(baseline, 'src/client_proxy_selector.rs')),
    build: 'CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/shoes/target cargo test --release --lib measurement_bench --no-run',
  },
  candidate: {
    revision: run('git', ['rev-parse', revision]),
    tree: run('git', ['rev-parse', `${revision}^{tree}`]),
    sources: Object.fromEntries([...new Set(sources)].map(p => {
      const bytes = execFileSync('git', ['show', `${revision}:${p}`]);
      if (hash(bytes) !== file(p).sha256) throw Error(`source differs from measured revision: ${p}`);
      return [p, { bytes: bytes.length, sha256: hash(bytes) }];
    })),
    build: 'CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/shoes/target taskset -c 0,1,3-7 cargo test --release --lib measurement_bench --no-run',
  },
  rustc: run('rustc', ['-Vv']),
  cpu: run('lscpu', ['--json']),
  allocator: 'System (lib unit test; the server binary uses jemalloc)',
  profile: 'release, fat LTO, codegen-units=1, default features, RUSTFLAGS unset',
  run: 'BENCH_CPU=2 BENCH_REPEATS=3 bash benches/run_selector.sh RESULTS/NAME-selector RESULTS/NAME.log',
  aggregate: 'node benches/compare_selector.mjs RESULTS/old.log RESULTS/new.log',
  checks: 'All 4096 queries per process verified before timing; counted stub DNS asserts exactly one lookup per measured DNS route.',
  artifacts,
  tooling: Object.fromEntries(['benches/run_selector.sh', 'benches/compare_selector.mjs', 'benches/selector_manifest.mjs'].map(p => [p, file(p)])),
}, null, 2));
