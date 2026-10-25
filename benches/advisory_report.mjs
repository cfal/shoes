import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const caseKey = r => [r.count, r.policies, r.mode, r.workload, r.ports].join('/');
const positive = n => Number.isFinite(n) && n > 0;
const digest = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const revision = s => typeof s === 'string' && /^[a-f0-9]{40}$/.test(s);
const require = (ok, message) => { if (!ok) throw Error(message); };

export function parseSelector(log) {
  require(!/^test result: FAILED/m.test(log), 'failed selector test');
  const records = [];
  for (const line of log.split('\n')) {
    const marker = line.indexOf('SELECTOR_BENCH ');
    if (marker < 0) continue;
    const r = JSON.parse(line.slice(marker + 'SELECTOR_BENCH '.length));
    require(Number.isSafeInteger(r.count) && r.count > 0 && Number.isSafeInteger(r.policies) &&
      r.policies > 0 && r.policies <= r.count, 'invalid selector dimensions');
    require(['ordinary', 'sniff', 'dns', 'warm', 'cold', 'floor'].includes(r.mode) &&
      ['mixed', 'early', 'late', 'miss'].includes(r.workload) &&
      ['none', 'fixed', 'mixed'].includes(r.ports), 'invalid selector workload');
    require(Array.isArray(r.samples) && r.samples.length === 15 && r.samples.every(positive) &&
      r.samples.every((n, i) => i === 0 || n >= r.samples[i - 1]), 'invalid selector samples');
    require(r.median_ns === r.samples[7] && r.batch_p95_ns === r.samples[14] &&
      Number.isFinite(r.build_ms) && r.build_ms >= 0 && Number.isSafeInteger(r.iterations) &&
      r.iterations >= 4 && r.iterations <= 262144, 'invalid selector summary');
    require(r.resolver_calls === (r.mode === 'dns' ? 15 * r.iterations : 0), 'invalid resolver count');
    records.push(r);
  }
  const successes = [...log.matchAll(/^test result: ok\. 1 passed; 0 failed;/gm)].length;
  require(records.length > 0 && successes === records.length, 'missing selector records or successful test counts');
  return records;
}

export function parseReload(log) {
  const r = JSON.parse(log);
  require(r.generations === 4 && Array.isArray(r.samples) && r.samples.length === 6,
    'expected warmup, four pinned generations and drained samples');
  require(positive(r.initial_load?.elapsed_ms), 'missing initial load timing');
  for (const s of [r.initial_load, ...r.samples]) {
    require(s && positive(s.rss_kib) && positive(s.high_water_kib) && s.high_water_kib >= s.rss_kib &&
      Number.isSafeInteger(s.fds) && s.fds > 0,
    'invalid reload sample');
  }
  for (const [s, phase] of [[r.samples[0], 'idle_warm'], [r.samples[5], 'drained']]) {
    require(s.phase === phase && s.pinned_connections === 0 && s.fds <= r.initial_load.fds,
      'invalid reload cleanup sample');
  }
  for (const [i, s] of r.samples.slice(1, 5).entries()) {
    require(s.phase === 'pinned' && s.generation === i && s.target === i % 2 &&
      s.pinned_connections === i + 1 && (i === 0 ? s.elapsed_ms === undefined : positive(s.elapsed_ms)),
    'invalid pinned generation');
  }
  require(positive(r.sampled_peak_rss_kib) &&
    [r.initial_load, ...r.samples].every(s => r.sampled_peak_rss_kib >= s.rss_kib),
  'missing or inconsistent reload RSS peak');
  require(revision(r.source?.revision) && digest(r.binary_sha256) &&
    Number.isSafeInteger(r.workers) && r.workers > 0 &&
    typeof r.profile === 'string' && r.profile !== 'unspecified' &&
    typeof r.source.build === 'string' && r.source.build.trim() &&
    Array.isArray(r.inputs) && r.inputs.length === 3 && r.inputs.every(i => digest(i.sha256)),
  'missing reload provenance');
  return r;
}

export function readMeasurement(directory) {
  const m = JSON.parse(fs.readFileSync(path.join(directory, 'measurement.json'), 'utf8'));
  require(m.schema === 2, 'unsupported measurement schema; recollect with the current upstream harness');
  require(revision(m.source?.revision) && revision(m.source.tree) &&
    digest(m.source.diff_sha256) && digest(m.source.lockfile_sha256) &&
    typeof m.source.dirty === 'boolean', 'missing source provenance');
  require(hash(fs.readFileSync(path.join(directory, 'source.diff'))) === m.source.diff_sha256,
    'missing or mismatched source patch');
  require(['debug', 'release'].includes(m.build?.profile) &&
    ['selector', 'server'].every(k => typeof m.build[k] === 'string' && m.build[k].trim()),
  'missing build commands/profile');
  require(['rustc', 'cargo', 'node', 'os', 'arch', 'cpu', 'affinity'].every(k =>
    typeof m.environment?.[k] === 'string' && m.environment[k].trim()) &&
    m.environment.flags && typeof m.environment.flags === 'object', 'missing environment');
  require(['selector', 'server', 'tooling'].every(k => digest(m.hashes?.[k])), 'missing artifact hashes');
  require(m.workload?.repeats === 3 && m.workload.workers === 1 && m.workload.generations === 4 &&
    Array.isArray(m.workload.selector) && m.workload.selector.length > 0 &&
    Array.isArray(m.workload.inputs) && m.workload.inputs.length === 3 && m.workload.inputs.every(digest),
  'invalid workload');
  require(Array.isArray(m.runs) && m.runs.length === 3 * (m.workload.selector.length + 1), 'missing runs');
  const metrics = new Map();
  const seen = new Map();
  const add = (name, value) => metrics.set(name, [...(metrics.get(name) || []), value]);
  const artifact = a => {
    require(a && typeof a.path === 'string' && path.basename(a.path) === a.path && digest(a.sha256),
      'invalid raw artifact');
    const p = path.join(directory, a.path);
    require(fs.statSync(p).size <= 10 * 1024 * 1024, 'oversized raw artifact');
    const bytes = fs.readFileSync(p);
    require(hash(bytes) === a.sha256, `raw artifact hash mismatch: ${a.path}`);
    return bytes.toString('utf8');
  };
  for (const r of m.runs) {
    require(r.status === 0 && r.signal === null && r.error === null, `failed run: ${r.id}`);
    const stdout = artifact(r.stdout);
    artifact(r.stderr);
    seen.set(r.id, (seen.get(r.id) || 0) + 1);
    if (r.id === 'reload') {
      const data = parseReload(stdout);
      require(data.source.revision === m.source.revision && data.binary_sha256 === m.hashes.server &&
        data.profile === m.build.profile && data.source.build === m.build.server &&
        data.workers === m.workload.workers &&
        JSON.stringify(data.inputs.map(i => i.sha256)) === JSON.stringify(m.workload.inputs),
      'reload provenance differs from measurement');
      add('reload/peak_rss_kib', data.sampled_peak_rss_kib);
      add('reload/initial_load/elapsed_ms', data.initial_load.elapsed_ms);
      for (const s of data.samples.slice(2, 5)) add(`reload/generation-${s.generation}/elapsed_ms`, s.elapsed_ms);
    } else {
      const data = parseSelector(stdout);
      require(data.length === 1 && r.id === caseKey(data[0]), 'selector case mismatch');
      add(`${r.id}/median_ns`, data[0].median_ns);
      add(`${r.id}/batch_p95_ns`, data[0].batch_p95_ns);
    }
  }
  const expected = [...m.workload.selector.map(caseKey), 'reload'];
  require(new Set(expected).size === expected.length && seen.size === expected.length &&
    expected.every(id => seen.get(id) === 3), 'missing, duplicate or unexpected cases');
  return { ...m, metrics };
}

export function compareMeasurements(baseline, candidate) {
  const report = {
    advisory: true, status: 'valid',
    baseline: { source: baseline.source, build: baseline.build, hashes: baseline.hashes },
    candidate: { source: candidate.source, build: candidate.build, hashes: candidate.hashes },
    warnings: ['Three fresh processes, fixed run order; range overlap and 5% are heuristics, not confidence intervals.',
      'Selector p95 is a batch-average tail. Tiny reload fixtures do not establish large-corpus or mobile memory bounds.'],
    metrics: [],
  };
  const differences = ['environment', 'workload'].filter(k =>
    JSON.stringify(baseline[k]) !== JSON.stringify(candidate[k]));
  if (baseline.build.profile !== candidate.build.profile) differences.push('build.profile');
  if (baseline.hashes.tooling !== candidate.hashes.tooling) differences.push('tooling');
  if (differences.length) {
    report.status = 'incomparable';
    report.warnings.push(`Different ${differences.join(', ')}; no deltas computed.`);
    return report;
  }
  require(baseline.metrics.size > 0 && baseline.metrics.size === candidate.metrics.size, 'missing metrics');
  const summary = xs => {
    require(Array.isArray(xs) && xs.length === 3 && xs.every(positive), 'invalid metric samples');
    const sorted = [...xs].sort((a, b) => a - b);
    return { min: sorted[0], median: sorted[1], max: sorted[2], samples: xs };
  };
  for (const [name, values] of baseline.metrics) {
    const old = summary(values), next = summary(candidate.metrics.get(name));
    const delta = 100 * (next.median / old.median - 1);
    const overlaps = next.min <= old.max && old.min <= next.max;
    report.metrics.push({ name, baseline: old, candidate: next, delta_percent: delta,
      observation: overlaps || Math.abs(delta) < 5 ? 'noise-unresolved' :
        delta > 0 ? 'candidate-higher' : 'candidate-lower' });
  }
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [baseline, candidate] = process.argv.slice(2);
    require(baseline && candidate, 'usage: node benches/advisory_report.mjs BASELINE_DIR CANDIDATE_DIR');
    const report = compareMeasurements(readMeasurement(baseline), readMeasurement(candidate));
    console.log(JSON.stringify(report, null, 2));
    if (report.status !== 'valid') process.exitCode = 1;
  } catch (error) {
    console.log(JSON.stringify({ advisory: true, status: 'invalid', errors: [error.message], metrics: [] }, null, 2));
    process.exitCode = 1;
  }
}
