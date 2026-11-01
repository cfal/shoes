import assert from 'node:assert/strict';
import test from 'node:test';
import { parseSamples } from './run_paths.mjs';

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
