import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const caseKey = record => [record.count, record.policies, record.mode, record.workload, record.ports].join('/');
const isPositive = value => Number.isFinite(value) && value > 0;
const isDigest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const isRevision = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);

function requireValid(condition, message) {
  if (!condition) throw Error(message);
}

export function parseSelector(log) {
  requireValid(!/^test result: FAILED/m.test(log), 'failed selector test');
  const records = [];
  for (const line of log.split('\n')) {
    const marker = line.indexOf('SELECTOR_BENCH ');
    if (marker < 0) continue;
    const record = JSON.parse(line.slice(marker + 'SELECTOR_BENCH '.length));
    requireValid(
      Number.isSafeInteger(record.count) && record.count > 0 &&
      Number.isSafeInteger(record.policies) && record.policies > 0 && record.policies <= record.count,
      'invalid selector dimensions',
    );
    requireValid(
      ['ordinary', 'sniff', 'dns', 'warm', 'cold', 'floor'].includes(record.mode) &&
      ['mixed', 'early', 'late', 'miss'].includes(record.workload) &&
      ['none', 'fixed', 'mixed'].includes(record.ports),
      'invalid selector workload',
    );
    requireValid(
      Array.isArray(record.samples) && record.samples.length === 15 && record.samples.every(isPositive) &&
      record.samples.every((sample, index) => index === 0 || sample >= record.samples[index - 1]),
      'invalid selector samples',
    );
    requireValid(
      record.median_ns === record.samples[7] && record.batch_p95_ns === record.samples[14] &&
      Number.isFinite(record.build_ms) && record.build_ms >= 0 &&
      Number.isSafeInteger(record.iterations) && record.iterations >= 4 && record.iterations <= 262144,
      'invalid selector summary',
    );
    const expectedResolverCalls = record.mode === 'dns' ? 15 * record.iterations : 0;
    requireValid(record.resolver_calls === expectedResolverCalls, 'invalid resolver count');
    records.push(record);
  }
  const successes = [...log.matchAll(/^test result: ok\. 1 passed; 0 failed;/gm)].length;
  requireValid(records.length > 0 && successes === records.length, 'missing selector records or successful test counts');
  return records;
}

export function parseReload(log) {
  const report = JSON.parse(log);
  requireValid(
    report.generations === 4 && Array.isArray(report.samples) && report.samples.length === 6,
    'expected warmup, four pinned generations and drained samples',
  );
  requireValid(isPositive(report.initial_load?.elapsed_ms), 'missing initial load timing');
  const allSamples = [report.initial_load, ...report.samples];
  for (const sample of allSamples) {
    requireValid(
      sample && isPositive(sample.rss_kib) && isPositive(sample.high_water_kib) &&
      sample.high_water_kib >= sample.rss_kib && Number.isSafeInteger(sample.fds) && sample.fds > 0,
      'invalid reload sample',
    );
  }
  const cleanupSamples = [[report.samples[0], 'idle_warm'], [report.samples[5], 'drained']];
  for (const [sample, phase] of cleanupSamples) {
    requireValid(
      sample.phase === phase && sample.pinned_connections === 0 && sample.fds <= report.initial_load.fds,
      'invalid reload cleanup sample',
    );
  }
  const pinnedSamples = report.samples.slice(1, 5);
  for (const [generation, sample] of pinnedSamples.entries()) {
    const validTiming = generation === 0 ? sample.elapsed_ms === undefined : isPositive(sample.elapsed_ms);
    requireValid(
      sample.phase === 'pinned' && sample.generation === generation && sample.target === generation % 2 &&
      sample.pinned_connections === generation + 1 && validTiming,
      'invalid pinned generation',
    );
  }
  requireValid(
    isPositive(report.sampled_peak_rss_kib) &&
    allSamples.every(sample => report.sampled_peak_rss_kib >= sample.rss_kib),
    'missing or inconsistent reload RSS peak',
  );
  requireValid(
    isRevision(report.source?.revision) && isDigest(report.binary_sha256) &&
    Number.isSafeInteger(report.workers) && report.workers > 0 &&
    typeof report.profile === 'string' && report.profile !== 'unspecified' &&
    typeof report.source.build === 'string' && report.source.build.trim() &&
    Array.isArray(report.inputs) && report.inputs.length === 3 && report.inputs.every(input => isDigest(input.sha256)),
    'missing reload provenance',
  );
  return report;
}

export function readMeasurement(directory) {
  const measurement = JSON.parse(fs.readFileSync(path.join(directory, 'measurement.json'), 'utf8'));
  requireValid(measurement.schema === 2, 'unsupported measurement schema; recollect with the current upstream harness');
  requireValid(
    isRevision(measurement.source?.revision) && isRevision(measurement.source.tree) &&
    isDigest(measurement.source.diff_sha256) && isDigest(measurement.source.lockfile_sha256) &&
    typeof measurement.source.dirty === 'boolean',
    'missing source provenance',
  );
  requireValid(
    hash(fs.readFileSync(path.join(directory, 'source.diff'))) === measurement.source.diff_sha256,
    'missing or mismatched source patch',
  );
  requireValid(
    ['debug', 'release'].includes(measurement.build?.profile) &&
    ['selector', 'server'].every(name => typeof measurement.build[name] === 'string' && measurement.build[name].trim()),
    'missing build commands/profile',
  );
  const environmentFields = ['rustc', 'cargo', 'node', 'os', 'arch', 'cpu', 'affinity'];
  requireValid(
    environmentFields.every(name =>
      typeof measurement.environment?.[name] === 'string' && measurement.environment[name].trim()) &&
    measurement.environment.flags && typeof measurement.environment.flags === 'object',
    'missing environment',
  );
  requireValid(
    ['selector', 'server', 'tooling'].every(name => isDigest(measurement.hashes?.[name])),
    'missing artifact hashes',
  );
  requireValid(
    measurement.workload?.repeats === 3 && measurement.workload.workers === 1 && measurement.workload.generations === 4 &&
    Array.isArray(measurement.workload.selector) && measurement.workload.selector.length > 0 &&
    Array.isArray(measurement.workload.inputs) && measurement.workload.inputs.length === 3 &&
    measurement.workload.inputs.every(isDigest),
    'invalid workload',
  );
  requireValid(
    Array.isArray(measurement.runs) && measurement.runs.length === 3 * (measurement.workload.selector.length + 1),
    'missing runs',
  );

  const metrics = new Map();
  const runCounts = new Map();
  function addMetric(name, value) {
    if (!metrics.has(name)) metrics.set(name, []);
    metrics.get(name).push(value);
  }
  function readArtifact(artifact) {
    requireValid(
      artifact && typeof artifact.path === 'string' &&
      path.basename(artifact.path) === artifact.path && isDigest(artifact.sha256),
      'invalid raw artifact',
    );
    const artifactPath = path.join(directory, artifact.path);
    requireValid(fs.statSync(artifactPath).size <= 10 * 1024 * 1024, 'oversized raw artifact');
    const bytes = fs.readFileSync(artifactPath);
    requireValid(hash(bytes) === artifact.sha256, `raw artifact hash mismatch: ${artifact.path}`);
    return bytes.toString('utf8');
  }
  for (const run of measurement.runs) {
    requireValid(run.status === 0 && run.signal === null && run.error === null, `failed run: ${run.id}`);
    const stdout = readArtifact(run.stdout);
    readArtifact(run.stderr);
    runCounts.set(run.id, (runCounts.get(run.id) || 0) + 1);
    if (run.id === 'reload') {
      const data = parseReload(stdout);
      requireValid(
        data.source.revision === measurement.source.revision && data.binary_sha256 === measurement.hashes.server &&
        data.profile === measurement.build.profile && data.source.build === measurement.build.server &&
        data.workers === measurement.workload.workers &&
        JSON.stringify(data.inputs.map(input => input.sha256)) === JSON.stringify(measurement.workload.inputs),
        'reload provenance differs from measurement',
      );
      addMetric('reload/peak_rss_kib', data.sampled_peak_rss_kib);
      addMetric('reload/initial_load/elapsed_ms', data.initial_load.elapsed_ms);
      const reloadSamples = data.samples.slice(2, 5);
      for (const sample of reloadSamples) {
        addMetric(`reload/generation-${sample.generation}/elapsed_ms`, sample.elapsed_ms);
      }
    } else {
      const records = parseSelector(stdout);
      requireValid(records.length === 1 && run.id === caseKey(records[0]), 'selector case mismatch');
      addMetric(`${run.id}/median_ns`, records[0].median_ns);
      addMetric(`${run.id}/batch_p95_ns`, records[0].batch_p95_ns);
    }
  }
  const expectedCases = [...measurement.workload.selector.map(caseKey), 'reload'];
  requireValid(
    new Set(expectedCases).size === expectedCases.length && runCounts.size === expectedCases.length &&
    expectedCases.every(id => runCounts.get(id) === 3),
    'missing, duplicate or unexpected cases',
  );
  return { ...measurement, metrics };
}

export function compareMeasurements(baseline, candidate) {
  const report = {
    advisory: true,
    status: 'valid',
    baseline: { source: baseline.source, build: baseline.build, hashes: baseline.hashes },
    candidate: { source: candidate.source, build: candidate.build, hashes: candidate.hashes },
    warnings: [
      'Three fresh processes, fixed run order; range overlap and 5% are heuristics, not confidence intervals.',
      'Selector p95 is a batch-average tail. Tiny reload fixtures do not establish large-corpus or mobile memory bounds.',
    ],
    metrics: [],
  };
  const differences = ['environment', 'workload'].filter(field =>
    JSON.stringify(baseline[field]) !== JSON.stringify(candidate[field]));
  if (baseline.build.profile !== candidate.build.profile) differences.push('build.profile');
  if (baseline.hashes.tooling !== candidate.hashes.tooling) differences.push('tooling');
  if (differences.length) {
    report.status = 'incomparable';
    report.warnings.push(`Different ${differences.join(', ')}; no deltas computed.`);
    return report;
  }
  requireValid(baseline.metrics.size > 0 && baseline.metrics.size === candidate.metrics.size, 'missing metrics');
  const summarize = samples => {
    requireValid(Array.isArray(samples) && samples.length === 3 && samples.every(isPositive), 'invalid metric samples');
    const sorted = [...samples].sort((a, b) => a - b);
    return { min: sorted[0], median: sorted[1], max: sorted[2], samples };
  };
  for (const [name, values] of baseline.metrics) {
    const baselineSummary = summarize(values);
    const candidateSummary = summarize(candidate.metrics.get(name));
    const delta = 100 * (candidateSummary.median / baselineSummary.median - 1);
    const overlaps = candidateSummary.min <= baselineSummary.max && baselineSummary.min <= candidateSummary.max;
    let observation;
    if (overlaps || Math.abs(delta) < 5) observation = 'noise-unresolved';
    else if (delta > 0) observation = 'candidate-higher';
    else observation = 'candidate-lower';
    report.metrics.push({
      name,
      baseline: baselineSummary,
      candidate: candidateSummary,
      delta_percent: delta,
      observation,
    });
  }
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [baseline, candidate] = process.argv.slice(2);
    requireValid(baseline && candidate, 'usage: node benches/advisory_report.mjs BASELINE_DIR CANDIDATE_DIR');
    const report = compareMeasurements(readMeasurement(baseline), readMeasurement(candidate));
    console.log(JSON.stringify(report, null, 2));
    if (report.status !== 'valid') process.exitCode = 1;
  } catch (error) {
    console.log(JSON.stringify({ advisory: true, status: 'invalid', errors: [error.message], metrics: [] }, null, 2));
    process.exitCode = 1;
  }
}
