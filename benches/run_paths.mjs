import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function validateRevision(root, revision) {
  const resolve = ref => execFileSync('git', ['-C', root, 'rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`], {
    encoding: 'utf8',
  }).trim();
  const commit = resolve(revision);
  if (commit !== resolve('HEAD')) throw Error('PATH_REVISION must match PATH_SOURCE_ROOT HEAD');
  return commit;
}

export function parseSamples(output, name, profile) {
  if (!['release', 'debug'].includes(profile)) throw Error('PATH_PROFILE must be release or debug');
  const lines = output.split('\n');
  const meta = lines.filter(line => line.startsWith('PATH_META,'));
  if (meta.length !== 1 || meta[0] !== `PATH_META,${name},debug_assertions=${profile === 'debug'}`) {
    throw Error(`profile/case mismatch: ${name}`);
  }
  if (!output.includes('test result: ok. 1 passed;')) throw Error(`measurement did not run: ${name}`);
  const samples = { prepare: [], 'select-false': [], 'select-true': [] };
  const seen = new Set();
  for (const line of lines.filter(line => line.startsWith('PATH,'))) {
    const fields = line.split(',');
    const [, phase, actual, sample, count, ns] = fields;
    const iterations = Number(count);
    const elapsedNs = Number(ns);
    const key = `${phase}/${sample}`;
    if (fields.length !== 6 || actual !== name || !Object.hasOwn(samples, phase)
      || !/^[0-6]$/.test(sample) || seen.has(key)
      || !Number.isSafeInteger(iterations) || iterations <= 0
      || !Number.isFinite(elapsedNs) || elapsedNs <= 0) {
      throw Error(`invalid sample: ${line}`);
    }
    seen.add(key);
    samples[phase].push(phase === 'prepare' ? elapsedNs : elapsedNs / iterations);
  }
  if (Object.values(samples).some(values => values.length !== 7)) throw Error(`incomplete samples: ${name}`);
  return samples;
}

function main() {
  const [binary, directory, matrix = 'full'] = process.argv.slice(2);
  if (!directory || !['fixed', 'full'].includes(matrix)) {
    throw Error('usage: node benches/run_paths.mjs TEST_BINARY NEW_OUTPUT_DIRECTORY [fixed|full]');
  }
  for (const name of ['PATH_BUILD_COMMAND', 'PATH_REVISION', 'PATH_PROFILE', 'PATH_SOURCE_ROOT']) {
    if (!process.env[name]) throw Error(`${name} is required`);
  }
  if (!['debug', 'release'].includes(process.env.PATH_PROFILE)) throw Error('PATH_PROFILE must be release or debug');
  const root = path.resolve(process.env.PATH_SOURCE_ROOT);
  const revision = validateRevision(root, process.env.PATH_REVISION);
  const cpu = process.env.BENCH_CPU || '2';
  const repeats = Number(process.env.BENCH_REPEATS || '3');
  if (!Number.isInteger(repeats) || repeats < 1 || repeats > 10) throw Error('BENCH_REPEATS must be 1..10');
  fs.mkdirSync(directory);
  const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  const hashFile = name => sha(fs.readFileSync(name));
  const sources = {};
  function collect(directory) {
    for (const item of fs.readdirSync(path.join(root, directory), { withFileTypes: true })) {
      const name = path.join(directory, item.name);
      if (item.isDirectory()) collect(name);
      else if (item.name.endsWith('.rs')) sources[name] = hashFile(path.join(root, name));
    }
  }
  collect('src');
  sources['benches/path_measurement.rs'] = hashFile(path.join(root, 'benches/path_measurement.rs'));
  const manifest = {
    revision,
    build: process.env.PATH_BUILD_COMMAND,
    profile: process.env.PATH_PROFILE,
    binary: path.resolve(binary),
    binary_sha256: hashFile(binary),
    lockfile_sha256: hashFile(path.join(root, 'Cargo.lock')),
    cargo_toml_sha256: hashFile(path.join(root, 'Cargo.toml')),
    cargo_config_sha256: hashFile(path.join(root, '.cargo/config.toml')),
    rustflags: process.env.RUSTFLAGS || '',
    cargo_encoded_rustflags: process.env.CARGO_ENCODED_RUSTFLAGS || '',
    debug_assertions: process.env.PATH_PROFILE === 'debug',
    harness_sha256: hashFile(new URL(import.meta.url)),
    rustc: execFileSync('rustc', ['-Vv'], { encoding: 'utf8' }),
    cpu, repeats, cpu_models: [...new Set(os.cpus().map(cpu => cpu.model))],
    load_before: os.loadavg(), sources,
  };
  fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2));
  const cases = ['fixed-1', 'fixed-4'];
  if (matrix === 'full') cases.push('rr-16', 'nested-64', 'nested-1024', 'deep-48', 'wide-16000', 'shared-64x64');
  const results = [];
  for (const name of cases) {
    const samples = { prepare: [], 'select-false': [], 'select-true': [] };
    for (let repeat = 0; repeat < repeats; repeat++) {
      let output;
      try {
        output = execFileSync('taskset', ['-c', cpu, path.resolve(binary),
          '--exact', 'client_proxy_chain::path_measurement::path_measurement', '--ignored', '--nocapture'], {
          env: { ...process.env, PATH_CASE: name }, encoding: 'utf8', timeout: 180_000,
        });
      } catch (error) {
        fs.writeFileSync(path.join(directory, `${name}-${repeat}.failed.log`), `${error.stdout || ''}\n${error.stderr || ''}`);
        throw error;
      }
      fs.writeFileSync(path.join(directory, `${name}-${repeat}.log`), output);
      for (const [phase, values] of Object.entries(parseSamples(output, name, process.env.PATH_PROFILE))) {
        samples[phase].push(...values);
      }
    }
    const result = { case: name };
    for (const [phase, values] of Object.entries(samples)) {
      values.sort((a, b) => a - b);
      result[phase] = { median_ns: values[Math.floor(values.length / 2)], min_ns: values[0], max_ns: values.at(-1) };
    }
    results.push(result);
    console.log(JSON.stringify(result));
  }
  fs.writeFileSync(path.join(directory, 'results.json'), JSON.stringify(results, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
