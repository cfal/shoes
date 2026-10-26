import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('shell guard requires a successful command and nonzero executed tests', t => {
  fs.mkdirSync('.workstream-evidence', { recursive: true });
  const tmp = fs.mkdtempSync(path.resolve('.workstream-evidence/test-guard-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  for (const [summary, code, expected] of [
    ['test result: ok. 1 passed; 0 failed;', 0, 0],
    ['test result: ok. 0 passed; 0 failed;', 0, 1],
    ['compiled only', 0, 1],
    ['test result: ok. 1 passed; 0 failed;', 9, 9],
  ]) {
    const result = spawnSync('bash', ['.github/require-tests.sh', process.execPath, '-e',
      `console.log(${JSON.stringify(summary)}); process.exit(${code});`], {
      env: { ...process.env, TMPDIR: tmp }, encoding: 'utf8',
    });
    assert.equal(result.status, expected, result.stderr);
  }
});
