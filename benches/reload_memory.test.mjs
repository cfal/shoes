import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
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

function createScratchDirectory() {
  const scratch = process.env.TMPDIR || path.join(os.homedir(), 'tmp');
  fs.mkdirSync(scratch, { recursive: true });
  return fs.mkdtempSync(path.join(scratch, 'reload-harness-test-'));
}

function killRecordedProcess(pidFile) {
  if (!fs.existsSync(pidFile)) return;
  try {
    const pid = Number(fs.readFileSync(pidFile, 'utf8'));
    if (!Number.isInteger(pid) || pid <= 0) return;
    process.kill(pid, 'SIGKILL');
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}

test('fixture cleanup signals only positive integer PIDs', t => {
  const directory = createScratchDirectory();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const pidFile = path.join(directory, 'fixture.pid');
  const kill = t.mock.method(process, 'kill', () => true);
  killRecordedProcess(pidFile);
  for (const contents of ['', ' \n', '0', '-1', '2.5', 'not-a-pid', 'Infinity']) {
    fs.writeFileSync(pidFile, contents);
    killRecordedProcess(pidFile);
  }
  assert.equal(kill.mock.callCount(), 0);
  fs.writeFileSync(pidFile, '12345\n');
  killRecordedProcess(pidFile);
  assert.deepEqual(kill.mock.calls.map(call => call.arguments), [[12345, 'SIGKILL']]);
});

function runHarness(t, source, {
  success = false,
  rustcSource,
  cwd = fileURLToPath(new URL('..', import.meta.url)),
  env = {},
} = {}) {
  const directory = createScratchDirectory();
  t.after(() => {
    if (rustcSource) {
      for (const name of ['rustc.pid', 'reload.json.pid']) {
        killRecordedProcess(path.join(directory, name));
      }
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const binary = path.join(directory, 'server.mjs');
  fs.writeFileSync(binary, `#!/usr/bin/env node\n${source}`, { mode: 0o755 });
  if (rustcSource) {
    fs.writeFileSync(path.join(directory, 'rustc'), `#!/usr/bin/env node\n${rustcSource}`, { mode: 0o755 });
  }
  const inputs = ['domains.yaml', 'cn.srs', 'us.srs'].map(name => path.join(directory, name));
  for (const input of inputs) fs.writeFileSync(input, 'fixture');
  const script = fileURLToPath(new URL('./reload_memory.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [script, binary,
    directory, ...inputs], {
    cwd,
    encoding: 'utf8', timeout: 10000,
    env: {
      ...process.env, ...env, BENCH_BUILD_COMMAND: 'test fixture', BENCH_GENERATIONS: '3',
      PATH: rustcSource ? `${directory}${path.delimiter}${process.env.PATH}` : process.env.PATH,
    },
  });
  assert.ifError(result.error);
  if (success) assert.equal(result.status, 0, result.stderr);
  else assert.notEqual(result.status, 0);
  return { result, directory, log: fs.readFileSync(path.join(directory, 'server.log'), 'utf8') };
}

test('reload harness fails and retains logs when a warmup stream closes', { skip: process.platform !== 'linux' }, t => {
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

function forwardingFixture({ reload, closeOnReload = false, retainFdOnReload = false }) {
  return `
import fs from 'node:fs';
import net from 'node:net';
const load = () => JSON.parse(fs.readFileSync(process.argv.at(-1), 'utf8')).at(-1);
let config = load();
const port = Number(config.address.split(':').at(-1));
const sockets = new Set();
net.createServer(socket => {
  sockets.add(socket);
  const target = Number(config.protocol.target.split(':').at(-1));
  const upstream = net.createConnection({ host: '127.0.0.1', port: target });
  socket.on('error', () => upstream.destroy());
  upstream.on('error', () => socket.destroy());
  socket.on('close', () => { sockets.delete(socket); upstream.destroy(); });
  socket.pipe(upstream).pipe(socket);
}).listen(port, '0.0.0.0', () => console.log('Servers ready'));
process.on('SIGHUP', () => {
  ${reload ? 'config = load();' : ''}
  ${closeOnReload ? 'for (const socket of sockets) socket.destroy();' : ''}
  ${retainFdOnReload ? "fs.openSync(process.argv.at(-1), 'r');" : ''}
  console.log('Servers ready');
});
`;
}

test('reload harness verifies target changes, exact payloads and drained FDs', { skip: process.platform !== 'linux' }, t => {
  const { result } = runHarness(t, forwardingFixture({ reload: true }), { success: true });
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.samples.map(s => s.phase), ['idle_warm', 'pinned', 'pinned', 'pinned', 'drained']);
  assert.deepEqual(report.samples.filter(s => s.phase === 'pinned').map(s => s.target), [0, 1, 0]);
  assert.ok(report.samples.at(-1).fds <= report.samples[0].fds);
  for (const sample of report.samples) assert.ok(sample.rss_kib > 0 && sample.fds > 0);
  for (const sample of [report.initial_load, ...report.samples]) {
    assert.ok(report.sampled_peak_rss_kib >= sample.rss_kib);
  }
  assert.match(report.harness_sha256, /^[0-9a-f]{64}$/);
  assert.match(report.server_log_sha256, /^[0-9a-f]{64}$/);
});

test('reload provenance preserves dirty patch bytes independently of Git settings', { skip: process.platform !== 'linux' }, t => {
  const cwd = createScratchDirectory();
  t.after(() => fs.rmSync(cwd, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', args, {
    cwd, env: { ...process.env, GIT_DIFF_OPTS: undefined },
  });
  git('init', '--quiet');
  fs.writeFileSync(path.join(cwd, 'Cargo.lock'), 'fixture\n');
  fs.writeFileSync(path.join(cwd, '.gitattributes'), 'fixture.txt diff=fixture\n');
  fs.writeFileSync(path.join(cwd, 'fixture.txt'), 'first\nbefore\nlast\n');
  fs.writeFileSync(path.join(cwd, 'fixture.bin'), Buffer.from([0, 1, 2]));
  git('add', 'Cargo.lock', '.gitattributes', 'fixture.txt', 'fixture.bin');
  git('-c', 'user.name=Harness Test', '-c', 'user.email=harness@example.invalid',
    '-c', 'commit.gpgSign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'fixture');
  fs.writeFileSync(path.join(cwd, 'fixture.txt'), Buffer.from('first\n\xff\nlast\n', 'latin1'));
  fs.writeFileSync(path.join(cwd, 'fixture.bin'), Buffer.from([0, 3, 4]));
  git('config', 'diff.noprefix', 'true');
  git('config', 'diff.mnemonicPrefix', 'true');
  git('config', 'color.ui', 'always');
  git('config', 'diff.external', 'false');
  git('config', 'diff.fixture.textconv', 'false');
  git('config', 'diff.context', '0');

  const { result } = runHarness(t, forwardingFixture({ reload: true }), {
    success: true, cwd, env: { GIT_DIFF_OPTS: '-u0' },
  });
  const report = JSON.parse(result.stdout);
  const patch = git('diff', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=3',
    '--src-prefix=a/', '--dst-prefix=b/', '--binary', 'HEAD');
  assert.ok(patch.length > 0);
  assert.ok(patch.includes(Buffer.from([0xff])));
  assert.ok(patch.includes(Buffer.from('GIT binary patch')));
  const recorded = Buffer.from(report.source.patch_base64, 'base64');
  assert.deepEqual(recorded, patch);
  assert.equal(report.source.patch_sha256, crypto.createHash('sha256').update(patch).digest('hex'));
  execFileSync('git', ['apply', '--reverse', '--check'], { cwd, input: recorded });
});

test('readiness alone cannot pass a reload with an unchanged datapath', { skip: process.platform !== 'linux' }, t => {
  const { result, log } = runHarness(t, forwardingFixture({ reload: false }));
  assert.match(result.stderr, /committed target not observed/);
  assert.equal(log.match(/Servers ready/g).length, 2);
});

test('reload harness rejects loss of a pinned connection after reload', { skip: process.platform !== 'linux' }, t => {
  const { result, log } = runHarness(t, forwardingFixture({ reload: true, closeOnReload: true }));
  assert.match(result.stderr, /premature echo close/);
  assert.equal(log.match(/Servers ready/g).length, 2);
});

test('reload harness rejects descriptors retained after reload', { skip: process.platform !== 'linux' }, t => {
  const { result, log } = runHarness(t, forwardingFixture({ reload: true, retainFdOnReload: true }));
  assert.match(result.stderr, /FD cleanup deadline/);
  assert.equal(log.match(/Servers ready/g).length, 3);
});

test('a stalled toolchain probe is killed and the server is cleaned up', { skip: process.platform !== 'linux' }, t => {
  const source = forwardingFixture({ reload: true }) + `
fs.writeFileSync(process.argv.at(-1) + '.pid', String(process.pid));
`;
  const rustcSource = `
import fs from 'node:fs';
fs.writeFileSync(process.argv[1] + '.pid', String(process.pid));
process.on('SIGTERM', () => {});
setTimeout(() => {}, 65000);
`;
  const { result, directory, log } = runHarness(t, source, { rustcSource });
  assert.match(result.stderr, /SIGKILL/);
  assert.equal(log.match(/Servers ready/g).length, 3);
  for (const name of ['rustc.pid', 'reload.json.pid']) {
    const pid = Number(fs.readFileSync(path.join(directory, name), 'utf8'));
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  }
});
