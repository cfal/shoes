import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseSamples, validateRevision } from './run_paths.mjs';

test('validates revision against the source checkout before collecting measurements', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'path-revision-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', [
    '-C', root, '-c', 'user.name=Benchmark test', '-c', 'user.email=benchmark@example.invalid',
    '-c', 'commit.gpgsign=false', ...args,
  ], { encoding: 'utf8' }).trim();
  git('init', '--quiet');
  git('commit', '--quiet', '--allow-empty', '-m', 'baseline');
  const baseline = git('rev-parse', 'HEAD');
  git('commit', '--quiet', '--allow-empty', '-m', 'candidate');
  const candidate = git('rev-parse', 'HEAD');
  for (const revision of ['HEAD', candidate, candidate.slice(0, 12)]) {
    assert.equal(validateRevision(root, revision), candidate);
  }
  assert.throws(() => validateRevision(root, baseline), /PATH_REVISION must match PATH_SOURCE_ROOT HEAD/);

  const directory = path.join(root, 'measurements');
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL('./run_paths.mjs', import.meta.url)), 'unused-binary', directory,
  ], {
    env: { ...process.env, PATH_BUILD_COMMAND: 'test fixture', PATH_PROFILE: 'release',
      PATH_SOURCE_ROOT: root, PATH_REVISION: baseline },
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PATH_REVISION must match PATH_SOURCE_ROOT HEAD/);
  assert.equal(fs.existsSync(directory), false);
});

function output(debug = false) {
  return [
    `PATH_META,fixed-1,debug_assertions=${debug}`,
    ...['prepare', 'select-false', 'select-true'].flatMap(phase =>
      Array.from({ length: 7 }, (_, sample) => `PATH,${phase},fixed-1,${sample},10,1000`)),
    'test result: ok. 1 passed; 0 failed;',
  ].join('\n');
}

test('accepts complete samples and normalizes only selection', () => {
  const samples = parseSamples(output(), 'fixed-1', 'release');
  assert.deepEqual(samples.prepare, Array(7).fill(1000));
  assert.deepEqual(samples['select-false'], Array(7).fill(100));
  assert.deepEqual(samples['select-true'], Array(7).fill(100));
  assert.deepEqual(parseSamples(output(true), 'fixed-1', 'debug'), samples);
});

test('rejects missing, repeated, or mismatched profile metadata', () => {
  for (const text of [
    output(true), output().replace(/^.*\n/, ''),
    `PATH_META,fixed-1,debug_assertions=false\n${output()}`,
    output().replace('PATH_META,fixed-1', 'PATH_META,fixed-4'),
  ]) assert.throws(() => parseSamples(text, 'fixed-1', 'release'), /profile\/case mismatch/);
  assert.throws(() => parseSamples(output(), 'fixed-1', 'other'), /PATH_PROFILE/);
});

test('rejects missing phases, duplicate samples, and out-of-range IDs', () => {
  for (const text of [
    output().replace(/PATH,select-true[^\n]*\n/g, ''),
    output().replaceAll('PATH,select-true', 'PATH,prepare'),
    output().replace('prepare,fixed-1,1,', 'prepare,fixed-1,0,'),
    output().replace('prepare,fixed-1,1,', 'prepare,fixed-1,7,'),
  ]) assert.throws(() => parseSamples(text, 'fixed-1', 'release'), /invalid sample|incomplete samples/);
});

test('rejects invalid counts, durations, fields, and unsuccessful tests', () => {
  for (const bad of ['NaN', 'Infinity', '0', '-1', '']) {
    for (const row of [`0,${bad},1000`, `0,10,${bad}`]) {
      assert.throws(() => parseSamples(output().replace('0,10,1000', row), 'fixed-1', 'release'), /invalid sample/);
    }
  }
  for (const row of ['0,1.5,1000', '0,9007199254740992,1000', '0,10,1000,extra']) {
    assert.throws(() => parseSamples(output().replace('0,10,1000', row), 'fixed-1', 'release'), /invalid sample/);
  }
  assert.throws(() => parseSamples(output().replace('1 passed', '0 passed'), 'fixed-1', 'release'), /did not run/);
});
