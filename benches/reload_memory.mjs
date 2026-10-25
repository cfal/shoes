import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import crypto from 'node:crypto';
import os from 'node:os';
import { promisify } from 'node:util';

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

export function parseStatus(status) {
  const kib = name => {
    const match = status.match(new RegExp(`^${name}:\\s+(\\d+) kB$`, 'm'));
    if (!match) throw Error(`missing or invalid ${name} in /proc status`);
    return Number(match[1]);
  };
  return { rss_kib: kib('VmRSS'), high_water_kib: kib('VmHWM') };
}

export function processUsage(pid) {
  if (process.platform !== 'linux') throw Error('reload memory/FD measurement requires Linux /proc');
  return {
    ...parseStatus(fs.readFileSync(`/proc/${pid}/status`, 'utf8')),
    fds: fs.readdirSync(`/proc/${pid}/fd`).length,
  };
}

export async function waitForFds(pid, maximum, { signal, timeout = 5000 } = {}) {
  const deadline = performance.now() + timeout;
  for (;;) {
    signal?.throwIfAborted();
    const sample = processUsage(pid);
    if (sample.fds <= maximum) return sample;
    if (performance.now() >= deadline) throw Error(`FD cleanup deadline: ${sample.fds} > ${maximum}`);
    await delay(10, undefined, { signal });
  }
}

async function main() {
  const [binary, directory, domains, cn, us] = process.argv.slice(2);
  if (!us) throw Error('usage: node benches/reload_memory.mjs BINARY SCRATCH_DIR DOMAINS_YAML CN_SRS US_SRS');
  const build = process.env.BENCH_BUILD_COMMAND;
  if (!build) throw Error('BENCH_BUILD_COMMAND must record the command used to build BINARY');
  if (process.platform !== 'linux') throw Error('reload memory/FD measurement requires Linux /proc');
  const generations = Number(process.env.BENCH_GENERATIONS || 4);
  if (!Number.isInteger(generations) || generations < 2 || generations > 16) {
    throw Error('BENCH_GENERATIONS must be 2..16');
  }
  const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  const hashFile = p => hash(fs.readFileSync(p));
  const git = args => execFileSync('git', args, { encoding: 'utf8' }).trim();
  const patch = execFileSync('git', [
    'diff', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=3',
    '--src-prefix=a/', '--dst-prefix=b/', '--binary', 'HEAD',
  ], {
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, GIT_DIFF_OPTS: undefined },
  });
  const source = {
    revision: git(['rev-parse', 'HEAD']),
    tree: git(['rev-parse', 'HEAD^{tree}']),
    tracked_tree_clean: git(['status', '--porcelain', '--untracked-files=no']) === '',
    build,
    patch_base64: patch.toString('base64'),
    patch_sha256: hash(patch),
    lockfile_sha256: hashFile('Cargo.lock'),
    untracked_sources: Object.fromEntries(
      git(['ls-files', '--others', '--exclude-standard', '-z', 'src', 'tests'])
        .split('\0')
        .filter(file => file.endsWith('.rs'))
        .map(file => [file, hashFile(file)]),
    ),
  };
  const workers = Number(process.env.BENCH_WORKERS || 1);
  if (!Number.isInteger(workers) || workers < 1) throw Error('BENCH_WORKERS must be a positive integer');
  const host = {
    platform: process.platform,
    arch: process.arch,
    cpu_models: [...new Set(os.cpus().map(cpu => cpu.model))],
    logical_cpus: os.cpus().length,
    loadavg_before: os.loadavg(),
  };
  fs.mkdirSync(directory, { recursive: true });
  if (fs.existsSync(path.join(directory, 'server.log'))) throw Error('refusing to overwrite server.log');
  const listen = async handler => {
    const server = net.createServer(handler);
    server.listen(0, '0.0.0.0');
    await once(server, 'listening');
    return server;
  };
  const echoSockets = new Set();
  const arrivals = [0, 0];
  const verifyTargetArrival = (before, target, message) => {
    const otherTarget = 1 - target;
    if (arrivals[target] !== before[target] + 1 || arrivals[otherTarget] !== before[otherTarget]) {
      throw Error(message);
    }
  };
  const echoes = [];
  for (let index = 0; index < 2; index++) {
    const echo = await listen(socket => {
      arrivals[index]++;
      echoSockets.add(socket);
      socket.on('error', () => socket.destroy());
      socket.on('close', () => echoSockets.delete(socket));
      socket.pipe(socket);
    });
    echoes.push(echo);
  }
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
    { address: `0.0.0.0:${port}`, protocol: { type: 'forward', target: `127.0.0.1:${echoes[0].address().port}` },
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
  const usage = () => processUsage(child.pid);
  let sampleError;
  const sampler = setInterval(() => {
    try {
      peak = Math.max(peak, usage().rss_kib);
    } catch (error) {
      // Exit can remove VmRSS before Node delivers the exit event. Preserve that
      // event's diagnostic, but never publish a successful run with missing samples.
      sampleError ??= error;
    }
  }, 10);
  child.stderr.on('data', b => { stderr += b; });
  child.stdout.on('data', b => {
    output += b;
    fragment += b;
    let i;
    while ((i = fragment.indexOf('\n')) !== -1) {
      const line = fragment.slice(0, i);
      fragment = fragment.slice(i + 1);
      if (line.includes('Servers ready')) {
        const value = { elapsed_ms: performance.now() - started };
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
  let report;
  try {
    const initial = await next();
    const idle = usage();
    const open = async () => {
      const socket = net.createConnection({ host: '127.0.0.1', port });
      connections.push(socket);
      socket.on('error', error => controller.abort(error));
      await once(socket, 'connect', { signal });
      return socket;
    };
    const warm = await open();
    await checkEcho(warm, 'warmup-exact-bytes', { signal });
    warm.destroy();
    connections.pop();
    samples.push({
      phase: 'idle_warm',
      pinned_connections: 0,
      ...await waitForFds(child.pid, idle.fds, { signal }),
    });
    for (let generation = 0; generation < generations; generation++) {
      const target = generation % 2;
      let loaded = {};
      if (generation) {
        config.at(-1).protocol.target = `127.0.0.1:${echoes[target].address().port}`;
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
        started = performance.now();
        child.kill('SIGHUP');
        loaded = await next();
      }
      const before = [...arrivals];
      await open();
      for (const connection of connections) {
        await checkEcho(connection, `retained-generation-${generation}\0exact-bytes`, { signal });
      }
      verifyTargetArrival(before, target, `generation ${generation}: committed target not observed in datapath`);
      samples.push({
        phase: 'pinned',
        generation,
        target,
        pinned_connections: connections.length,
        ...loaded,
        ...usage(),
      });
    }
    for (const socket of connections) socket.destroy();
    connections.length = 0;
    await waitForFds(child.pid, idle.fds, { signal });
    const before = [...arrivals];
    const probe = await open();
    await checkEcho(probe, 'post-drain-exact-bytes', { signal });
    const finalTarget = (generations - 1) % 2;
    verifyTargetArrival(before, finalTarget, 'post-drain committed target not observed in datapath');
    probe.destroy();
    connections.pop();
    samples.push({
      phase: 'drained',
      pinned_connections: 0,
      ...await waitForFds(child.pid, idle.fds, { signal }),
    });
    const { stdout: rustc } = await promisify(execFile)('rustc', ['-Vv'], {
      encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL', signal,
    });
    if (sampleError) throw sampleError;
    report = {
      source,
      binary_sha256: hashFile(binary),
      allocator: 'server jemalloc',
      profile: process.env.BENCH_PROFILE || 'unspecified',
      workers,
      samples,
      sampled_peak_rss_kib: Math.max(peak, idle.rss_kib, ...samples.map(sample => sample.rss_kib)),
      initial_load: { ...initial, ...idle },
      generations,
      host: { ...host, loadavg_after: os.loadavg() },
      harness_sha256: hashFile(fileURLToPath(import.meta.url)),
      rustc: rustc.trim(),
      command: process.argv,
      contention: process.env.BENCH_CONTENTION || 'not recorded',
      inputs: [domains, cn, us].map(p => ({ path: p, sha256: hashFile(p) })),
      scope: 'Exact-byte TCP checks pin one selector per generation. Alternating upstreams verify committed datapath, then FDs return to idle within 5s. Linux RSS/HWM are informational, not live heap, async tasks, leak proof, or a mobile budget.',
    };
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
    for (const echo of echoes) echo.close();
    fs.writeFileSync(path.join(directory, 'server.log'), output + stderr);
  }
  report.server_log_sha256 = hashFile(path.join(directory, 'server.log'));
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
