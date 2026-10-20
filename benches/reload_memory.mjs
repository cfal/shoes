import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import crypto from 'node:crypto';

const [binary, directory, domains, cn, us] = process.argv.slice(2);
if (!us) throw Error('usage: node benches/reload_memory.mjs BINARY SCRATCH_DIR DOMAINS_YAML CN_SRS US_SRS');
const workers = Number(process.env.BENCH_WORKERS || 1);
fs.mkdirSync(directory, { recursive: true });
const listen = async handler => {
  const server = net.createServer(handler);
  server.listen(0, '0.0.0.0');
  await once(server, 'listening');
  return server;
};
const echo = await listen(socket => socket.pipe(socket));
const reservation = await listen();
const port = reservation.address().port;
reservation.close();
await once(reservation, 'close');
const config = [
  { global_limits: { reload_grace_secs: 60 } },
  { rule_set: 'domains', path: path.resolve(domains), format: 'mihomo_yaml', behavior: 'domain' },
  { rule_set: 'cn', path: path.resolve(cn) },
  { rule_set: 'us', path: path.resolve(us) },
  { address: `0.0.0.0:${port}`, protocol: { type: 'forward', target: `127.0.0.1:${echo.address().port}` },
    rules: [{ rule_sets: ['domains', 'cn', 'us'], action: 'block' },
      { match: { any_destination: true }, action: 'allow' }] },
];
const configPath = path.join(directory, 'reload.json');
fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
const child = spawn(binary, ['-t', String(workers), '--no-reload', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
const exited = once(child, 'exit');
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
const next = () => ready.length ? Promise.resolve(ready.shift()) : Promise.race([
  new Promise(resolve => pending.push(resolve)),
  exited.then(code => { throw Error(`server exited: ${code}; ${stderr}`); }),
]);
const timeout = setTimeout(() => { child.kill('SIGKILL'); }, 60000);
const samples = [];
try {
  for (let generation = 0; generation < 4; generation++) {
    if (generation) { started = performance.now(); child.kill('SIGHUP'); }
    const loaded = await next();
    const socket = net.createConnection({ host: '127.0.0.1', port });
    await once(socket, 'connect');
    connections.push(socket);
    for (const connection of connections) {
      const received = once(connection, 'data');
      connection.write('retained-generation');
      const [bytes] = await received;
      if (bytes.toString() !== 'retained-generation') throw Error('incorrect echo');
    }
    samples.push({ generation, pinned_connections: connections.length, ...loaded });
  }
  const hash = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  console.log(JSON.stringify({ binary_sha256: hash(binary), allocator: 'server jemalloc',
    profile: process.env.BENCH_PROFILE || 'unspecified', workers, samples, sampled_peak_rss_kib: peak,
    inputs: [domains, cn, us].map(p => ({ path: p, sha256: hash(p) })),
    scope: 'One live TCP connection per generation keeps old selector indexes pinned; four generations, three SIGHUP reloads. Linux RSS/HWM, not requested heap or a mobile budget.',
  }, null, 2));
} finally {
  clearInterval(sampler);
  clearTimeout(timeout);
  for (const socket of connections) socket.destroy();
  child.kill('SIGTERM');
  await exited;
  echo.close();
  fs.writeFileSync(path.join(directory, 'server.log'), output + stderr);
}
