import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import crypto from 'node:crypto';

export function checkEcho(socket, message, { signal, timeout = 5000 } = {}) {
  const deadline = AbortSignal.timeout(timeout);
  const stop = signal ? AbortSignal.any([signal, deadline]) : deadline;
  const expected = Buffer.from(message);
  return new Promise((resolve, reject) => {
    const received = Buffer.alloc(expected.length);
    let length = 0;
    const finish = error => {
      socket.off('data', data);
      socket.off('end', closed);
      socket.off('close', closed);
      socket.off('error', failed);
      stop.removeEventListener('abort', aborted);
      if (error) reject(error);
      else resolve();
    };
    const data = bytes => {
      if (length + bytes.length > expected.length) return finish(Error('excess echo bytes'));
      bytes.copy(received, length);
      length += bytes.length;
      if (length === expected.length) {
        finish(received.equals(expected) ? undefined : Error('incorrect echo'));
      }
    };
    const closed = () => finish(Error(`premature echo close: ${length}/${expected.length} bytes`));
    const failed = error => finish(error);
    const aborted = () => finish(stop.reason);
    socket.on('data', data);
    socket.once('end', closed);
    socket.once('close', closed);
    socket.once('error', failed);
    stop.addEventListener('abort', aborted, { once: true });
    if (stop.aborted) aborted();
    else if (socket.destroyed || socket.readableEnded) closed();
    else socket.write(expected);
  });
}

async function main() {
  const [binary, directory, domains, cn, us] = process.argv.slice(2);
  if (!us) throw Error('usage: node benches/reload_memory.mjs BINARY SCRATCH_DIR DOMAINS_YAML CN_SRS US_SRS');
  const build = process.env.BENCH_BUILD_COMMAND;
  if (!build) throw Error('BENCH_BUILD_COMMAND must record the command used to build BINARY');
  const git = args => execFileSync('git', args, { encoding: 'utf8' }).trim();
  const source = {
    revision: git(['rev-parse', 'HEAD']),
    tree: git(['rev-parse', 'HEAD^{tree}']),
    tracked_tree_clean: git(['status', '--porcelain', '--untracked-files=no']) === '',
    build,
  };
  const workers = Number(process.env.BENCH_WORKERS || 1);
  fs.mkdirSync(directory, { recursive: true });
  const listen = async handler => {
    const server = net.createServer(handler);
    server.listen(0, '0.0.0.0');
    await once(server, 'listening');
    return server;
  };
  const echoSockets = new Set();
  const echo = await listen(socket => {
    echoSockets.add(socket);
    socket.on('error', () => socket.destroy());
    socket.on('close', () => echoSockets.delete(socket));
    socket.pipe(socket);
  });
  const reservation = await listen();
  const port = reservation.address().port;
  reservation.close();
  await once(reservation, 'close');
  const config = [
    { global_limits: { reload_grace_secs: 60 } },
    { rule_group: 'imported', rules: [
      { path: path.resolve(domains), format: 'mihomo_yaml', behavior: 'domain' },
      path.resolve(cn),
      path.resolve(us),
    ] },
    { address: `0.0.0.0:${port}`, protocol: { type: 'forward', target: `127.0.0.1:${echo.address().port}` },
      rules: [{ masks: { rule_group: 'imported' }, action: 'block' },
        { masks: { any_destination: true }, action: 'allow' }] },
  ];
  const configPath = path.join(directory, 'reload.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  const child = spawn(binary, ['-t', String(workers), '--no-reload', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = new Promise(resolve => child.once('close', resolve));
  const controller = new AbortController();
  const { signal } = controller;
  const stopped = new Promise(resolve => signal.addEventListener('abort', () => resolve(signal.reason), { once: true }));
  const exited = new Promise(resolve => {
    child.once('error', error => { controller.abort(error); resolve(); });
    child.once('exit', (code, exitSignal) => {
      controller.abort(Error(`server exited: code=${code}, signal=${exitSignal}`));
      resolve();
    });
  });
  const connections = [];
  const ready = [];
  const pending = [];
  let output = '', stderr = '', fragment = '', started = performance.now(), peak = 0;
  const rss = () => {
    try {
      const status = fs.readFileSync(`/proc/${child.pid}/status`, 'utf8');
      const kib = name => Number(status.match(new RegExp(`^${name}:\\s+(\\d+)`, 'm'))?.[1] || 0);
      return { rss_kib: kib('VmRSS'), high_water_kib: kib('VmHWM') };
    } catch { return { rss_kib: 0, high_water_kib: 0 }; }
  };
  const sampler = setInterval(() => { peak = Math.max(peak, rss().rss_kib); }, 10);
  child.stderr.on('data', b => { stderr += b; });
  child.stdout.on('data', b => {
    output += b;
    fragment += b;
    let i;
    while ((i = fragment.indexOf('\n')) !== -1) {
      const line = fragment.slice(0, i);
      fragment = fragment.slice(i + 1);
      if (line.includes('Servers ready')) {
        const value = { elapsed_ms: performance.now() - started, ...rss() };
        if (pending.length) pending.shift()(value);
        else ready.push(value);
      }
    }
  });
  const next = () => Promise.race([
    ready.length ? Promise.resolve(ready.shift()) : new Promise(resolve => pending.push(resolve)),
    stopped.then(error => { throw error; }),
  ]);
  const timeout = setTimeout(() => {
    controller.abort(Error('reload measurement timed out'));
    child.kill('SIGKILL');
  }, 60000);
  const samples = [];
  try {
    for (let generation = 0; generation < 4; generation++) {
      if (generation) { started = performance.now(); child.kill('SIGHUP'); }
      const loaded = await next();
      const socket = net.createConnection({ host: '127.0.0.1', port });
      connections.push(socket);
      socket.on('error', error => controller.abort(error));
      await once(socket, 'connect', { signal });
      for (const connection of connections) {
        await checkEcho(connection, 'retained-generation', { signal });
      }
      samples.push({ generation, pinned_connections: connections.length, ...loaded });
    }
    const hash = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
    console.log(JSON.stringify({ source, binary_sha256: hash(binary), allocator: 'server jemalloc',
      profile: process.env.BENCH_PROFILE || 'unspecified', workers, samples, sampled_peak_rss_kib: peak,
      inputs: [domains, cn, us].map(p => ({ path: p, sha256: hash(p) })),
      scope: 'One live TCP connection per generation keeps old selector indexes pinned; four generations, three SIGHUP reloads. Linux RSS/HWM, not requested heap or a mobile budget.',
    }, null, 2));
  } finally {
    clearInterval(sampler);
    clearTimeout(timeout);
    for (const socket of connections) socket.destroy();
    child.kill('SIGTERM');
    const kill = setTimeout(() => child.kill('SIGKILL'), 2000);
    await exited;
    clearTimeout(kill);
    await Promise.race([closed, delay(1000, undefined, { ref: false })]);
    child.stdout.destroy();
    child.stderr.destroy();
    for (const socket of echoSockets) socket.destroy();
    echo.close();
    fs.writeFileSync(path.join(directory, 'server.log'), output + stderr);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
