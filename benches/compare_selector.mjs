import fs from 'node:fs';
import { parseSelector } from './advisory_report.mjs';

const [oldPath, newPath] = process.argv.slice(2);
if (!oldPath || !newPath) throw Error('usage: node benches/compare_selector.mjs OLD.log NEW.log');
const key = r => [r.count, r.policies, r.mode, r.workload, r.ports].join('/');
const median = xs => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
function read(path) {
  const groups = new Map();
  for (const r of parseSelector(fs.readFileSync(path, 'utf8'))) {
    const id = key(r);
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(r);
  }
  if (groups.size !== 58) throw Error(`${path}: expected 58 cases, found ${groups.size}`);
  return new Map([...groups].map(([id, runs]) => {
    if (runs.length !== 3) throw Error(`${id}: expected three processes`);
    return [id, { ...runs[0], median_ns: median(runs.map(r => r.median_ns)),
      min_ns: Math.min(...runs.map(r => r.median_ns)), max_ns: Math.max(...runs.map(r => r.median_ns)),
      build_ms: median(runs.map(r => r.build_ms)) }];
  }));
}
const old = read(oldPath), next = read(newPath);
const cases = [];
for (const [id, r] of next) {
  const baseline = old.get(id);
  if (!baseline) throw Error(`missing baseline ${id}`);
  let limit;
  if (r.mode !== 'floor') {
    if (r.policies > 1 || r.count === 16) {
      limit = baseline.median_ns + Math.max(baseline.median_ns * 0.25, 250);
    } else if (r.count === 100000) {
      const small = next.get(key({ ...r, count: 16 })).median_ns;
      limit = Math.min(10000, Math.max(4 * small, small + 1000));
    } else {
      const medium = next.get(key({ ...r, count: 100000 })).median_ns;
      limit = Math.max(2 * medium, medium + 1000);
    }
  }
  cases.push({ case: id, old_ns: baseline.median_ns, new_ns: r.median_ns,
    old_min_ns: baseline.min_ns, old_max_ns: baseline.max_ns,
    new_min_ns: r.min_ns, new_max_ns: r.max_ns,
    old_build_ms: baseline.build_ms, new_build_ms: r.build_ms,
    limit_ns: limit ?? null, pass: limit === undefined || r.median_ns <= limit });
}
console.log(JSON.stringify({ processes: 348, cases, failures: cases.filter(c => !c.pass) }, null, 2));
if (cases.some(c => !c.pass)) process.exitCode = 1;
