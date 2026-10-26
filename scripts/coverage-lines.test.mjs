import assert from 'node:assert/strict';
import test from 'node:test';
import { changedCoverage, changedLines, coverageLines } from './coverage-lines.mjs';

const diff = 'diff --git a/src/a.rs b/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1,3 @@\n+a\n+b\n+c\n';
const lcov = 'SF:src/a.rs\nDA:1,3\nDA:2,0\nend_of_record\n';

test('changed lines distinguish covered, uncovered and unknown/non-executable', () => {
  const report = changedCoverage(diff, lcov);
  assert.equal(report.percent, 50);
  assert.deepEqual(report.files[0].covered, [1]);
  assert.deepEqual(report.files[0].uncovered, [2]);
  assert.deepEqual(report.files[0].not_in_report, [3]);
});
test('empty diff and deletion-only hunks are N/A, not 100 percent', () => {
  assert.equal(changedCoverage('', lcov).percent, null);
  assert.deepEqual([...changedLines(diff.replace('+1,3', '+1,0')).get('src/a.rs')], []);
});
test('deleted files contribute no candidate lines, including rename-as-delete/add diffs', () => {
  const deletion = 'diff --git a/src/old.rs b/src/old.rs\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n';
  assert.equal(changedCoverage(deletion, lcov).percent, null);
  assert.equal(changedCoverage(deletion + diff, lcov).percent, 50);
});
test('added source text resembling a file header cannot change the current file', () => {
  const report = changedCoverage(diff + '+++ b/wrong.rs\n@@ -9 +9 @@\n+text\n', lcov);
  assert.equal(report.files.length, 1);
  assert.equal(report.files[0].file, 'src/a.rs');
  assert.deepEqual(report.files[0].not_in_report, [3, 9]);
});
test('missing file coverage remains unknown', () => {
  const report = changedCoverage(diff.replaceAll('a.rs', 'b.rs'), lcov);
  assert.equal(report.percent, null);
  assert.equal(report.files[0].instrumented, false);
  assert.deepEqual(report.files[0].not_in_report, [1, 2, 3]);
});
test('LCOV merges duplicate file instantiations without double counting lines', () => {
  const report = changedCoverage(diff, lcov + lcov.replace('DA:2,0', 'DA:2,4'));
  assert.equal(report.percent, 100);
  assert.equal(report.changed_executable_lines, 2);
});
test('zero-line, malformed, missing and incomplete coverage fails closed', () => {
  for (const input of ['', 'SF:src/a.rs\nend_of_record', lcov.replace('DA:1,3', 'DA:1,-1'),
    'DA:1,2\n', lcov.replace('end_of_record', ''), lcov.replace('DA:1,3', 'DA:0,2')]) {
    assert.throws(() => coverageLines(input));
  }
});
test('quoted paths and malformed hunk context fail explicitly', () => {
  assert.throws(() => changedLines('+++ "b/weird path"\n@@ -1 +1 @@'));
  assert.throws(() => changedLines('@@ -1 +1 @@'));
});

test('classification preserves hunk order, deduplicates lines and retains empty file records', () => {
  const changes = [
    'diff --git a/src/a.rs b/src/a.rs',
    '+++ b/src/a.rs',
    '@@ -9 +9,2 @@',
    '+late',
    '+unknown',
    '@@ -1 +1,2 @@',
    '+covered',
    '+uncovered',
    '@@ -9 +9 @@',
    '+duplicate',
    'diff --git a/src/b.rs b/src/b.rs',
    '+++ b/src/b.rs',
    '@@ -1 +1 @@',
    '+uninstrumented',
  ].join('\n');
  const counts = 'SF:src/a.rs\nDA:1,3\nDA:2,0\nDA:9,1\nend_of_record\nSF:src/b.rs\nend_of_record\n';
  const report = changedCoverage(changes, counts);
  assert.deepEqual(report.files, [
    { file: 'src/a.rs', changed_lines: 4, instrumented: true, covered: [9, 1], uncovered: [2], not_in_report: [10] },
    { file: 'src/b.rs', changed_lines: 1, instrumented: true, covered: [], uncovered: [], not_in_report: [1] },
  ]);
  assert.equal(report.changed_executable_lines, 3);
  assert.equal(report.percent, 200 / 3);
});

test('malformed LCOV retains specific validation diagnostics', () => {
  const cases = [
    ['SF:src/a.rs\nSF:src/b.rs\n', 'unterminated LCOV record'],
    ['DA:1,1\n', 'invalid LCOV line count'],
    ['SF:src/a.rs\nDA:1,9007199254740992\n', 'invalid LCOV line count'],
    ['end_of_record\n', 'LCOV terminator without file'],
    ['SF:src/a.rs\nend_of_record\n', 'empty or incomplete coverage'],
  ];
  for (const [input, message] of cases) {
    assert.throws(() => coverageLines(input), { message });
  }
});
