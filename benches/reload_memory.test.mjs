import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
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

test('reload harness fails and retains logs when a pinned stream closes', t => {
  const directory = fs.mkdtempSync(path.join(os.homedir(), 'tmp/reload-harness-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const binary = path.join(directory, 'server.mjs');
  fs.writeFileSync(binary, `#!/usr/bin/env node
import fs from 'node:fs';
import net from 'node:net';
const config = JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8'));
const port = Number(config.at(-1).address.split(':').at(-1));
net.createServer(socket => socket.once('data', () => socket.end()))
  .listen(port, '0.0.0.0', () => console.log('Servers ready'));
process.on('SIGTERM', () => {});
`, { mode: 0o755 });
  const result = spawnSync(process.execPath, ['benches/reload_memory.mjs', binary,
    directory, 'unused.yaml', 'unused-cn.srs', 'unused-us.srs'], {
    encoding: 'utf8', timeout: 10000,
    env: { ...process.env, BENCH_BUILD_COMMAND: 'test fixture' },
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /premature echo close/);
  assert.match(fs.readFileSync(path.join(directory, 'server.log'), 'utf8'), /Servers ready/);
});
