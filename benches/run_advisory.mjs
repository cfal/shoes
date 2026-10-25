import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { hash, caseKey, readMeasurement } from './advisory_report.mjs';

const [selectorPath, serverPath, output] = process.argv.slice(2);
if (!output) throw Error('usage: node benches/run_advisory.mjs SELECTOR_TEST_BINARY SHOES_BINARY NEW_OUTPUT_DIR');
const selector = path.resolve(selectorPath), server = path.resolve(serverPath);
const build = { profile: process.env.BENCH_PROFILE,
  selector: process.env.BENCH_SELECTOR_BUILD_COMMAND, server: process.env.BENCH_BUILD_COMMAND };
if (!['debug', 'release'].includes(build.profile) || !build.selector?.trim() || !build.server?.trim()) {
  throw Error('set BENCH_PROFILE, BENCH_SELECTOR_BUILD_COMMAND and BENCH_BUILD_COMMAND to actual build provenance');
}
const run = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8' }).trim();
const git = args => run('git', args);
const fileHash = p => hash(fs.readFileSync(p));
fs.mkdirSync(output); // Refuse stale or overwritten measurements.
const directory = path.resolve(output);
const domains = path.join(directory, 'domains.yaml');
fs.writeFileSync(domains, 'payload:\n  - exact.example\n  - +.suffix.example\n');
const inputs = [domains, path.resolve('tests/fixtures/rule_sets/singbox-v2.srs'),
  path.resolve('tests/fixtures/rule_sets/singbox-v2.srs')];
const workload = { repeats: 3, workers: 1, generations: 4, inputs: inputs.map(fileHash), selector: [
  { count: 16, policies: 1, mode: 'ordinary', workload: 'mixed', ports: 'none' },
  { count: 12800, policies: 128, mode: 'ordinary', workload: 'late', ports: 'mixed' },
] };
const manifest = {
  schema: 2, started_at: new Date().toISOString(),
  source: { revision: git(['rev-parse', 'HEAD']), tree: git(['rev-parse', 'HEAD^{tree}']),
    dirty: git(['status', '--porcelain']) !== '', diff_sha256: hash(git(['diff', '--binary', 'HEAD'])),
    lockfile_sha256: fileHash('Cargo.lock') },
  environment: { rustc: run('rustc', ['-Vv']), cargo: run('cargo', ['-V']), node: process.version,
    os: `${os.platform()} ${os.release()}`, arch: os.arch(), cpu: os.cpus()[0]?.model || 'unknown',
    affinity: fs.readFileSync('/proc/self/status', 'utf8').match(/^Cpus_allowed_list:\s+(.+)$/m)?.[1] || 'unknown',
    flags: Object.fromEntries(['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS',
      'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_PROFILE_RELEASE_LTO',
      'CARGO_PROFILE_RELEASE_CODEGEN_UNITS', 'CARGO_BUILD_TARGET'].map(k => [k, process.env[k] ?? null])) },
  build, workload,
  hashes: { selector: fileHash(selector), server: fileHash(server),
    tooling: hash(['benches/selector_measurement.rs', 'benches/reload_memory.mjs',
      'benches/run_advisory.mjs', 'benches/advisory_report.mjs'].map(fileHash).join('\n')) },
  allocators: { selector: 'system', reload: 'jemalloc' },
  runs: [],
};
// Preserve the actual dirty patch and untracked verification sources, not only HEAD.
fs.writeFileSync(path.join(directory, 'source.diff'), git(['diff', '--binary', 'HEAD']));
manifest.sources = Object.fromEntries(git(['ls-files', '--cached', '--others', '--exclude-standard',
  'src', 'tests', 'benches', 'Cargo.toml', 'Cargo.lock']).split('\n')
  .filter(p => /\.(rs|toml|lock|mjs|sh)$/.test(p) && fs.existsSync(p)).sort().map(p => [p, fileHash(p)]));
const save = () => fs.writeFileSync(path.join(directory, 'measurement.json'), JSON.stringify(manifest, null, 2));
save();
function measure(id, command, args, env, timeout) {
  const result = spawnSync(command, args, { env: { ...process.env, ...env }, encoding: 'utf8',
    timeout, killSignal: 'SIGKILL', maxBuffer: 10 * 1024 * 1024 });
  const prefix = `run-${manifest.runs.length}`;
  const artifact = (suffix, bytes) => {
    const name = `${prefix}.${suffix}`;
    fs.writeFileSync(path.join(directory, name), bytes || '');
    return { path: name, sha256: hash(bytes || '') };
  };
  manifest.runs.push({ id, command: [command, ...args], env, timeout_ms: timeout,
    status: result.status, signal: result.signal, error: result.error?.message ?? null,
    stdout: artifact('stdout', result.stdout), stderr: artifact('stderr', result.stderr) });
  save();
}
for (let repeat = 0; repeat < workload.repeats; repeat++) {
  for (const c of workload.selector) {
    measure(caseKey(c), selector, ['client_proxy_selector::measurement_bench::selector_measurement',
      '--ignored', '--exact', '--nocapture', '--test-threads=1'],
    Object.fromEntries(Object.entries(c).map(([k, v]) => [`BENCH_${k.toUpperCase()}`, String(v)])), 15000);
  }
  measure('reload', process.execPath, ['benches/reload_memory.mjs', server,
    path.join(directory, `reload-${repeat}`), ...inputs],
  { BENCH_WORKERS: '1', BENCH_GENERATIONS: String(workload.generations),
    BENCH_PROFILE: build.profile, BENCH_BUILD_COMMAND: build.server }, 70000);
}
try {
  readMeasurement(directory);
  console.log(`Valid advisory measurement: ${directory} (6 selector tests, 3 four-generation reload runs)`);
} catch (error) {
  console.error(`Invalid measurement retained at ${directory}: ${error.message}`);
  process.exitCode = 1;
}
