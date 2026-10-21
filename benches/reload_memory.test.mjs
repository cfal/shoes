import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { checkEcho } from './reload_memory.mjs';

async function connected(t, handle) {
  const server = net.createServer(socket => {
    t.after(() => socket.destroy());
    socket.on('error', () => socket.destroy());
    handle(socket);
  });
  server.listen(0, '0.0.0.0');
  await once(server, 'listening');
  t.after(() => server.close());
  const socket = net.createConnection({ host: '127.0.0.1', port: server.address().port });
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  return socket;
}

test('echo accumulates separate TCP chunks', async t => {
  const socket = await connected(t, peer => peer.once('data', bytes => {
    peer.write(bytes.subarray(0, 3));
    setTimeout(() => peer.write(bytes.subarray(3)), 20);
  }));
  await checkEcho(socket, 'retained-generation');
});

test('echo rejects orderly EOF after a partial response', async t => {
  const socket = await connected(t, peer => peer.once('data', () => peer.end('partial')));
  await assert.rejects(checkEcho(socket, 'retained-generation'), /premature echo close/);
});

test('echo rejects a connection closed without a response', async t => {
  const socket = await connected(t, peer => peer.once('data', () => peer.destroy()));
  await assert.rejects(checkEcho(socket, 'retained-generation'), /premature echo close/);
});

test('echo rejects a stalled stream within its deadline', async t => {
  const socket = await connected(t, () => {});
  await assert.rejects(checkEcho(socket, 'retained-generation', { timeout: 20 }), { name: 'TimeoutError' });
});

test('server exit aborts a pending echo', async t => {
  const controller = new AbortController();
  const socket = await connected(t, peer => peer.once('data', () => controller.abort(Error('server exited'))));
  await assert.rejects(checkEcho(socket, 'retained-generation', { signal: controller.signal }), /server exited/);
});

test('echo rejects incorrect and excess bytes', async t => {
  for (const response of ['wrong', 'too many bytes']) {
    const socket = await connected(t, peer => peer.once('data', () => peer.write(response)));
    await assert.rejects(checkEcho(socket, 'hello'), /incorrect echo|excess echo bytes/);
  }
});

function runHarness(t, source) {
  const scratch = path.join(os.homedir(), 'tmp');
  fs.mkdirSync(scratch, { recursive: true });
  const directory = fs.mkdtempSync(path.join(scratch, 'reload-harness-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const binary = path.join(directory, 'server.mjs');
  fs.writeFileSync(binary, `#!/usr/bin/env node\n${source}`, { mode: 0o755 });
  const script = fileURLToPath(new URL('./reload_memory.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, binary,
    directory, 'unused.yaml', 'unused-cn.srs', 'unused-us.srs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    encoding: 'utf8', timeout: 10000,
    env: { ...process.env, BENCH_BUILD_COMMAND: 'test fixture' },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  return { result, log: fs.readFileSync(path.join(directory, 'server.log'), 'utf8') };
}

test('reload harness fails and retains logs when a pinned stream closes', t => {
  const { result, log } = runHarness(t, `
import fs from 'node:fs';
import net from 'node:net';
const config = JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8'));
const port = Number(config.at(-1).address.split(':').at(-1));
net.createServer(socket => socket.once('data', () => socket.end()))
  .listen(port, '0.0.0.0', () => console.log('Servers ready'));
process.on('SIGTERM', () => {});
`);
  assert.match(result.stderr, /premature echo close/);
  assert.match(log, /Servers ready/);
});

test('reload harness drains output pipes after the server exits', t => {
  // An inherited pipe keeps the final output pending until after the server exits.
  const writer = `setTimeout(() => {
    process.stdout.write('x'.repeat(1024 * 1024) + 'FINAL OUTPUT\\n');
    process.stderr.write('FINAL ERROR\\n');
  }, 100);`;
  const { result, log } = runHarness(t, `
import { spawn } from 'node:child_process';
spawn(process.execPath, ['-e', ${JSON.stringify(writer)}], { stdio: ['ignore', 1, 2] }).unref();
process.exit(9);
`);
  assert.match(result.stderr, /server exited: code=9/);
  assert.equal(log, 'x'.repeat(1024 * 1024) + 'FINAL OUTPUT\nFINAL ERROR\n');
});
