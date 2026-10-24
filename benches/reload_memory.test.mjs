import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { checkEcho, parseStatus, processUsage, waitForFds } from './reload_memory.mjs';

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

function runHarness(t, source, { success = false } = {}) {
  const scratch = process.env.TMPDIR || path.join(os.homedir(), 'tmp');
  fs.mkdirSync(scratch, { recursive: true });
  const directory = fs.mkdtempSync(path.join(scratch, 'reload-harness-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const binary = path.join(directory, 'server.mjs');
  fs.writeFileSync(binary, `#!/usr/bin/env node\n${source}`, { mode: 0o755 });
  const inputs = ['domains.yaml', 'cn.srs', 'us.srs'].map(name => path.join(directory, name));
  for (const input of inputs) fs.writeFileSync(input, 'fixture');
  const script = fileURLToPath(new URL('./reload_memory.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, binary,
    directory, ...inputs], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    encoding: 'utf8', timeout: 10000,
    env: { ...process.env, BENCH_BUILD_COMMAND: 'test fixture', BENCH_GENERATIONS: '3' },
  });
  assert.ifError(result.error);
  if (success) assert.equal(result.status, 0, result.stderr);
  else assert.notEqual(result.status, 0);
  return { result, log: fs.readFileSync(path.join(directory, 'server.log'), 'utf8') };
}

test('reload harness fails and retains logs when a pinned stream closes', { skip: process.platform !== 'linux' }, t => {
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

test('reload harness drains output pipes after the server exits', { skip: process.platform !== 'linux' }, t => {
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

test('proc metrics reject unavailable data instead of reporting zero', () => {
  assert.deepEqual(parseStatus('VmRSS:\t100 kB\nVmHWM:\t120 kB\n'), { rss_kib: 100, high_water_kib: 120 });
  assert.throws(() => parseStatus('VmRSS:\t100 kB\n'), /VmHWM/);
  assert.throws(() => parseStatus('VmRSS: broken\nVmHWM: 120 kB\n'), /VmRSS/);
  assert.throws(() => processUsage('missing-process'));
});

test('FD cleanup does not accept a stable retained descriptor count', { skip: process.platform !== 'linux' }, async () => {
  await assert.rejects(waitForFds(process.pid, 0, { timeout: 20 }), /FD cleanup deadline/);
});

function forwardingFixture(reload) {
  return `
import fs from 'node:fs';
import net from 'node:net';
const load = () => JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8')).at(-1);
let config = load();
const port = Number(config.address.split(':').at(-1));
net.createServer(socket => {
  const target = Number(config.protocol.target.split(':').at(-1));
  const upstream = net.createConnection({ host: '127.0.0.1', port: target });
  socket.on('error', () => upstream.destroy());
  upstream.on('error', () => socket.destroy());
  socket.on('close', () => upstream.destroy());
  socket.pipe(upstream).pipe(socket);
}).listen(port, '0.0.0.0', () => console.log('Servers ready'));
process.on('SIGHUP', () => { ${reload ? 'config = load();' : ''} console.log('Servers ready'); });
`;
}

test('reload harness verifies target changes, exact payloads and drained FDs', { skip: process.platform !== 'linux' }, t => {
  const { result } = runHarness(t, forwardingFixture(true), { success: true });
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.samples.map(s => s.phase), ['idle_warm', 'pinned', 'pinned', 'pinned', 'drained']);
  assert.deepEqual(report.samples.filter(s => s.phase === 'pinned').map(s => s.target), [0, 1, 0]);
  assert.ok(report.samples.at(-1).fds <= report.samples[0].fds);
  for (const sample of report.samples) assert.ok(sample.rss_kib > 0 && sample.fds > 0);
  assert.match(report.harness_sha256, /^[0-9a-f]{64}$/);
  assert.match(report.server_log_sha256, /^[0-9a-f]{64}$/);
});

test('readiness alone cannot pass a reload with an unchanged datapath', { skip: process.platform !== 'linux' }, t => {
  const { result, log } = runHarness(t, forwardingFixture(false));
  assert.match(result.stderr, /committed target not observed/);
  assert.equal(log.match(/Servers ready/g).length, 2);
});
