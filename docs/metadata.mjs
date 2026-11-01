import { execFileSync } from 'node:child_process';

function localRef() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: new URL('..', import.meta.url),
      encoding: 'utf8',
    }).trim();
  } catch {
    return 'unknown';
  }
}

const explicitRef = process.env.SHOES_DOCS_REF;
if (explicitRef !== undefined && !/^[0-9a-f]{40}$/.test(explicitRef)) {
  throw new Error('SHOES_DOCS_REF must be a full lowercase commit SHA');
}

export const sourceRef = explicitRef ?? localRef();
export const sourceRefKnown = /^[0-9a-f]{40}$/.test(sourceRef);
export const docsLabel = process.env.SHOES_DOCS_LABEL || 'dev';
