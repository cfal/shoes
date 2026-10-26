import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function changedLines(diff) {
  const files = new Map();
  let file;
  let inHunk = false;
  for (const line of diff.split('\n')) {
    if (line.startsWith('diff --git ')) {
      file = undefined;
      inHunk = false;
    }
    if (line.startsWith('+++ ') && !inHunk) {
      if (line === '+++ /dev/null') {
        file = null;
        continue;
      }
      if (!line.startsWith('+++ b/')) throw Error('unsupported quoted diff path');
      file = line.slice(6);
    }
    const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (!match) continue;
    inHunk = true;
    if (file === undefined) throw Error('hunk without file');
    const start = Number(match[1]);
    const count = Number(match[2] ?? 1);
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(count) || count > 1000000) {
      throw Error('invalid hunk');
    }
    if (file === null) {
      if (count !== 0) throw Error('deleted file has added lines');
      continue;
    }
    if (!files.has(file)) files.set(file, new Set());
    const changed = files.get(file);
    for (let number = start; number < start + count; number++) changed.add(number);
  }
  return files;
}

export function coverageLines(lcov, root = process.cwd()) {
  const files = new Map();
  let lines;
  for (const line of lcov.split('\n')) {
    if (line.startsWith('SF:')) {
      if (lines) throw Error('unterminated LCOV record');
      const file = path.relative(root, path.resolve(root, line.slice(3)));
      if (!files.has(file)) files.set(file, new Map());
      lines = files.get(file);
    } else if (line.startsWith('DA:')) {
      const match = /^DA:([1-9]\d*),(\d+)(?:,[^,]+)?$/.exec(line);
      if (!lines || !match) throw Error('invalid LCOV line count');
      const number = Number(match[1]);
      const count = Number(match[2]);
      if (!Number.isSafeInteger(number) || !Number.isSafeInteger(count)) {
        throw Error('invalid LCOV line count');
      }
      const previous = lines.get(number) || 0;
      lines.set(number, Math.max(previous, count));
    } else if (line === 'end_of_record') {
      if (!lines) throw Error('LCOV terminator without file');
      lines = undefined;
    }
  }
  if (lines || ![...files.values()].some(counts => counts.size > 0)) {
    throw Error('empty or incomplete coverage');
  }
  return files;
}

export function changedCoverage(diff, lcov, root) {
  const coverage = coverageLines(lcov, root);
  const files = [...changedLines(diff)].map(([file, changed]) => {
    const counts = coverage.get(file);
    const covered = [];
    const uncovered = [];
    const notInReport = [];
    for (const number of changed) {
      if (!counts?.has(number)) notInReport.push(number);
      else if (counts.get(number) > 0) covered.push(number);
      else uncovered.push(number);
    }
    return {
      file,
      changed_lines: changed.size,
      instrumented: Boolean(counts),
      covered,
      uncovered,
      not_in_report: notInReport,
    };
  });
  const covered = files.reduce((total, file) => total + file.covered.length, 0);
  const executable = covered + files.reduce((total, file) => total + file.uncovered.length, 0);
  return {
    scope: 'Linux unit/process only; no peers, privileged, FFI or device coverage',
    changed_executable_lines: executable,
    covered,
    percent: executable ? 100 * covered / executable : null,
    note: 'not_in_report means non-executable OR uninstrumented, never implicitly covered. Untracked files are not in git diff.',
    files,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [diff, lcov] = process.argv.slice(2);
  if (!lcov) throw Error('usage: node scripts/coverage-lines.mjs CHANGES.diff COVERAGE.lcov');
  const report = changedCoverage(fs.readFileSync(diff, 'utf8'), fs.readFileSync(lcov, 'utf8'));
  console.log(JSON.stringify(report, null, 2));
}
