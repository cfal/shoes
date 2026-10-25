import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { caseKey, hash, parseSelector, parseReload, readMeasurement, compareMeasurements } from './advisory_report.mjs';

const sha = 'a'.repeat(64), rev = 'b'.repeat(40);
const selector = () => ({ count: 16, policies: 1, mode: 'ordinary', workload: 'mixed', ports: 'none',
  build_ms: 1, median_ns: 100, batch_p95_ns: 100, samples: Array(15).fill(100), iterations: 10, resolver_calls: 0 });
const log = r => `SELECTOR_BENCH ${JSON.stringify(r)}\ntest result: ok. 1 passed; 0 failed; 0 ignored\n`;
const reload = () => ({ source: { revision: rev, build: 'cargo build --locked' }, binary_sha256: sha,
  profile: 'debug', workers: 1, inputs: Array(3).fill({ sha256: sha }), sampled_peak_rss_kib: 100,
  generations: 4, initial_load: { elapsed_ms: 7, rss_kib: 90, high_water_kib: 100, fds: 10 },
  samples: [
    { phase: 'idle_warm', pinned_connections: 0, rss_kib: 90, high_water_kib: 100, fds: 10 },
    ...Array.from({ length: 4 }, (_, generation) => ({ phase: 'pinned', generation, target: generation % 2,
      pinned_connections: generation + 1, ...(generation ? { elapsed_ms: generation } : {}),
      rss_kib: 90, high_water_kib: 100, fds: 12 + generation * 2 })),
    { phase: 'drained', pinned_connections: 0, rss_kib: 90, high_water_kib: 100, fds: 10 },
  ] });

test('existing selector records and reload format are parsed without changing sample meaning', () => {
  assert.equal(parseSelector(log(selector()))[0].median_ns, 100);
  const r = reload();
  assert.deepEqual(parseReload(JSON.stringify(r)), r);
});

test('selector rejects missing, malformed and zero-sample logs', () => {
  for (const value of ['', 'SELECTOR_BENCH {', log({ ...selector(), samples: [] }),
    log({ ...selector(), samples: Array(15).fill(0) }), log({ ...selector(), median_ns: null }),
    log({ ...selector(), iterations: 0 }), log({ ...selector(), resolver_calls: 1 }),
    log({ ...selector(), build_ms: -1 }), log(selector()).replace('1 passed', '0 passed'),
    log(selector()) + 'test result: FAILED']) {
    assert.throws(() => parseSelector(value));
  }
});

test('reload rejects missing phases, generations, timings, resource samples and provenance', () => {
  for (const change of [r => { r.samples = []; }, r => { r.sampled_peak_rss_kib = 0; },
    r => { r.samples[2].generation = 0; }, r => { r.samples[2].elapsed_ms = null; },
    r => { r.samples[1].elapsed_ms = 1; }, r => { r.samples[2].target = 0; },
    r => { r.samples[2].pinned_connections = 1; }, r => { r.samples[0].phase = 'drained'; },
    r => { r.samples[5].phase = 'idle_warm'; }, r => { r.samples[5].pinned_connections = 1; },
    r => { r.samples[5].fds = 11; }, r => { r.samples[0].fds = 11; },
    r => { r.samples[1].fds = 0; }, r => { r.samples[1].fds = 1.5; },
    r => { r.samples[0].rss_kib = 0; }, r => { r.samples[0].high_water_kib = 1; },
    r => { r.sampled_peak_rss_kib = 89; }, r => { r.samples[1] = null; },
    r => { delete r.initial_load; }, r => { r.initial_load.elapsed_ms = 0; },
    r => { r.generations = 3; }, r => { r.source = {}; }, r => { r.inputs = []; }]) {
    const r = reload(); change(r);
    assert.throws(() => parseReload(JSON.stringify(r)));
  }
  assert.throws(() => parseReload('{'));
});

test('legacy reload reports are rejected rather than relabelled as upstream lifecycle evidence', () => {
  const r = reload();
  delete r.generations;
  delete r.initial_load;
  r.samples = r.samples.slice(1, 5).map(({ phase, target, fds, ...s }) => ({ ...s, elapsed_ms: 1 }));
  assert.throws(() => parseReload(JSON.stringify(r)), /warmup/);
});

function fixture(t) {
  const directory = fs.mkdtempSync(path.resolve('.workstream-evidence/advisory-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'source.diff'), '');
  const m = { schema: 2, source: { revision: rev, tree: rev, diff_sha256: hash(''), lockfile_sha256: sha, dirty: true },
    build: { profile: 'debug', selector: 'cargo test --locked', server: 'cargo build --locked' },
    hashes: { selector: sha, server: sha, tooling: sha },
    environment: { rustc: 'rustc', cargo: 'cargo', node: '24', os: 'linux', arch: 'x64', cpu: 'cpu', affinity: '0', flags: {} },
    workload: { repeats: 3, workers: 1, generations: 4, inputs: [sha, sha, sha], selector: [selector()] }, runs: [] };
  for (let i = 0; i < 3; i++) {
    for (const [id, stdout] of [[caseKey(selector()), log(selector())], ['reload', JSON.stringify(reload())]]) {
      const artifact = (suffix, text) => {
        const name = `${m.runs.length}.${suffix}`;
        fs.writeFileSync(path.join(directory, name), text);
        return { path: name, sha256: hash(text) };
      };
      m.runs.push({ id, status: 0, signal: null, error: null,
        stdout: artifact('stdout', stdout), stderr: artifact('stderr', '') });
    }
  }
  const save = () => fs.writeFileSync(path.join(directory, 'measurement.json'), JSON.stringify(m));
  save();
  return { directory, m, save };
}
fs.mkdirSync('.workstream-evidence', { recursive: true });

test('reload metrics separate initial startup from the three reload readiness timings', t => {
  const { directory } = fixture(t);
  const { metrics } = readMeasurement(directory);
  assert.deepEqual(metrics.get('reload/initial_load/elapsed_ms'), [7, 7, 7]);
  assert.equal(metrics.has('reload/generation-0/elapsed_ms'), false);
  for (let generation = 1; generation < 4; generation++) {
    assert.deepEqual(metrics.get(`reload/generation-${generation}/elapsed_ms`), Array(3).fill(generation));
  }
});

test('self-comparison is valid but unresolved, with raw samples retained', t => {
  const { directory } = fixture(t);
  const m = readMeasurement(directory);
  const report = compareMeasurements(m, m);
  assert.equal(report.status, 'valid');
  assert.equal(report.metrics.length, 7);
  assert.ok(report.metrics.every(r => r.observation === 'noise-unresolved' && r.baseline.samples.length === 3));
});

test('large regressions are visible but are not timing gates', t => {
  const { directory } = fixture(t);
  const old = readMeasurement(directory), next = readMeasurement(directory);
  next.metrics = new Map([...old.metrics].map(([k, xs]) => [k, xs.map(x => x * 2)]));
  const report = compareMeasurements(old, next);
  assert.equal(report.status, 'valid');
  assert.ok(report.metrics.every(r => r.observation === 'candidate-higher' && r.delta_percent === 100));
});

test('overlap and sub-five-percent differences remain noise-unresolved', t => {
  const { directory } = fixture(t);
  const old = readMeasurement(directory), next = readMeasurement(directory);
  old.metrics = new Map([['overlap', [80, 100, 200]], ['small', [100, 100, 100]]]);
  next.metrics = new Map([['overlap', [100, 150, 300]], ['small', [104, 104, 104]]]);
  assert.ok(compareMeasurements(old, next).metrics.every(r => r.observation === 'noise-unresolved'));
});

for (const field of ['environment', 'workload', 'profile', 'tooling']) {
  test(`different ${field} is incomparable, never an improvement`, t => {
    const { directory } = fixture(t);
    const old = readMeasurement(directory), next = readMeasurement(directory);
    if (field === 'profile') next.build.profile = 'release';
    else if (field === 'tooling') next.hashes.tooling = 'c'.repeat(64);
    else next[field].changed = true;
    const report = compareMeasurements(old, next);
    assert.equal(report.status, 'incomparable');
    assert.deepEqual(report.metrics, []);
  });
}

test('missing runs, failures, stale hashes, duplicated cases and incomplete metadata are invalid', t => {
  const { directory, m, save } = fixture(t);
  for (const mutate of [m => m.runs.pop(), m => { m.runs[0].status = 1; },
    m => { m.runs[0].signal = 'SIGKILL'; }, m => { m.runs[0].error = 'timeout'; },
    m => { m.runs[0].stdout.sha256 = sha; }, m => { m.runs[0].id = 'reload'; },
    m => { m.runs[0].stdout.path = '../escape'; }, m => { m.workload.repeats = 0; },
    m => { m.source.revision = ''; }, m => { m.source.diff_sha256 = sha; }, m => { m.build.profile = 'unspecified'; },
    m => { m.environment = {}; }, m => { m.schema = 1; }, m => { m.workload.generations = 3; }]) {
    const original = structuredClone(m);
    mutate(m); save();
    assert.throws(() => readMeasurement(directory));
    Object.assign(m, original);
  }
  save();
  fs.unlinkSync(path.join(directory, m.runs[0].stdout.path));
  assert.throws(() => readMeasurement(directory));
});

test('CLI emits invalid status and no metrics for missing artifacts', t => {
  const { directory } = fixture(t);
  const result = spawnSync(process.execPath, ['benches/advisory_report.mjs', directory, `${directory}/missing`], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.deepEqual(JSON.parse(result.stdout).metrics, []);
  assert.equal(JSON.parse(result.stdout).status, 'invalid');
});

test('collector retains failed processes and raw diagnostics instead of dropping runs', t => {
  const { directory } = fixture(t);
  const output = path.join(directory, 'failed-collection');
  // Node is deliberately not a Rust test executable or a Shoes server.
  const result = spawnSync(process.execPath,
    ['benches/run_advisory.mjs', process.execPath, process.execPath, output], {
      encoding: 'utf8', timeout: 15000,
      env: { ...process.env, BENCH_PROFILE: 'debug', BENCH_GENERATIONS: '16',
        BENCH_SELECTOR_BUILD_COMMAND: 'invalid test fixture', BENCH_BUILD_COMMAND: 'invalid test fixture' },
    });
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  const m = JSON.parse(fs.readFileSync(path.join(output, 'measurement.json'), 'utf8'));
  assert.equal(m.runs.length, 9);
  assert.equal(m.schema, 2);
  assert.equal(m.workload.generations, 4);
  assert.ok(m.runs.filter(r => r.id === 'reload').every(r => r.env.BENCH_GENERATIONS === '4'));
  assert.ok(m.runs.every(r => r.status !== 0));
  assert.ok(m.runs.every(r => fs.statSync(path.join(output, r.stderr.path)).size > 0));
  assert.throws(() => readMeasurement(output), /failed run/);
});
