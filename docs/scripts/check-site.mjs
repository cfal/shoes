import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseHTML } from 'linkedom';
import { fromMarkdown } from 'mdast-util-from-markdown';

const root = fileURLToPath(new URL('../dist/', import.meta.url));
const files = [];
const stats = new Map();
function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (entry.name.endsWith('.html')) files.push(file);
  }
}
walk(root);

const pages = new Map();
for (const file of files) {
  const { document } = parseHTML(readFileSync(file, 'utf8'));
  const ids = new Set([...document.querySelectorAll('[id]')].map((node) => node.id));
  pages.set(file, { document, ids });
}

const errors = [];
function checkSiteLink(source, href, base) {
  const url = new URL(href, base);
  if (url.origin !== 'https://shoes-rs.github.io') return;
  const route = decodeURIComponent(url.pathname);
  const target = path.join(root, route, route.endsWith('/') ? 'index.html' : '');
  const targetFile = statSyncSafe(target)?.isDirectory() ? path.join(target, 'index.html') : target;
  if (!statSyncSafe(targetFile)?.isFile()) {
    errors.push(`${source}: missing ${href}`);
  } else if (url.hash && targetFile.endsWith('.html') && !pages.get(targetFile)?.ids.has(decodeURIComponent(url.hash.slice(1)))) {
    errors.push(`${source}: missing anchor ${href}`);
  }
}

for (const [file, { document }] of pages) {
  const chinese = path.relative(root, file).startsWith(`zh-cn${path.sep}`);
  const expectedLang = chinese ? 'zh-CN' : 'en';
  if (document.documentElement.lang !== expectedLang) {
    errors.push(`${path.relative(root, file)}: expected ${expectedLang} page language`);
  }
  const version = document.querySelector(`header [aria-label="${chinese ? '文档版本' : 'Documentation version'}"]`);
  const sourceRef = document.querySelector('meta[name="shoes-source-ref"]')?.getAttribute('content');
  if (!version?.hasAttribute('data-pagefind-ignore')) {
    errors.push(`${path.relative(root, file)}: missing header version metadata`);
  }
  if (/^[0-9a-f]{40}$/.test(sourceRef ?? '')) {
    if (!version?.querySelector(`a[href="https://github.com/cfal/shoes/commit/${sourceRef}"]`)) {
      errors.push(`${path.relative(root, file)}: missing header source link`);
    }
  } else if (version?.querySelector('a')) {
    errors.push(`${path.relative(root, file)}: unexpected source link for unknown revision`);
  }
  if (!document.querySelector(`header a[href="https://github.com/cfal/shoes"][aria-label="${chinese ? 'GitHub 上的 shoes' : 'shoes on GitHub'}"]`)) {
    errors.push(`${path.relative(root, file)}: missing header repository link`);
  }
  const languages = document.querySelector('header starlight-lang-select select');
  const languagePaths = [...(languages?.querySelectorAll('option') ?? [])].map((option) => option.value);
  if (!document.querySelector('header .mobile-language starlight-lang-select svg.label-icon') ||
      !languagePaths.some((value) => value.startsWith('/zh-cn/')) ||
      !languagePaths.some((value) => value.startsWith('/') && !value.startsWith('/zh-cn/'))) {
    errors.push(`${path.relative(root, file)}: missing header language selector`);
  }
  for (const link of document.querySelectorAll('a[href]')) {
    const href = link.getAttribute('href');
    if (href) checkSiteLink(path.relative(root, file), href, `https://shoes-rs.github.io/${path.relative(root, file)}`);
  }
}

function statSyncSafe(file) {
  if (!stats.has(file)) {
    try { stats.set(file, statSync(file)); } catch { stats.set(file, null); }
  }
  return stats.get(file);
}

function* markdownLinks(node) {
  if (node.type === 'link' || node.type === 'definition') yield node.url;
  for (const child of node.children ?? []) yield* markdownLinks(child);
}

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
for (const name of ['README.md', 'CHANGELOG.md']) {
  const file = path.join(repositoryRoot, name);
  for (const href of markdownLinks(fromMarkdown(readFileSync(file, 'utf8')))) {
    const url = new URL(href, pathToFileURL(file));
    if (url.origin === 'https://shoes-rs.github.io') {
      checkSiteLink(name, href, pathToFileURL(file));
    } else if (url.protocol === 'file:' && !statSyncSafe(fileURLToPath(url))) {
      errors.push(`${name}: missing ${href}`);
    }
  }
}

const docsRoot = fileURLToPath(new URL('../src/content/docs/', import.meta.url));
function codeNodes(file) {
  const content = readFileSync(file, 'utf8').replace(/^---\n[\s\S]*?\n---\n/, '');
  const blocks = [];
  const inline = [];
  function visit(node) {
    if (node.type === 'code') blocks.push(node.value);
    if (node.type === 'inlineCode') inline.push(node.value.replace(/\s+/g, ' '));
    for (const child of node.children ?? []) visit(child);
  }
  visit(fromMarkdown(content));
  return { blocks, inline };
}
function checkTranslations(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'zh-cn') continue;
    const source = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      checkTranslations(source);
    } else if (entry.name.endsWith('.md') || entry.name.endsWith('.mdx')) {
      const translated = path.join(docsRoot, 'zh-cn', path.relative(docsRoot, source));
      if (!statSyncSafe(translated)?.isFile()) {
        errors.push(`Missing Chinese page: ${path.relative(docsRoot, source)}`);
      } else if (entry.name.endsWith('.md')) {
        const original = codeNodes(source);
        const translation = codeNodes(translated);
        if (JSON.stringify(original.blocks) !== JSON.stringify(translation.blocks)) {
          errors.push(`Changed code block in Chinese page: ${path.relative(docsRoot, source)}`);
        }
        for (const value of original.inline) {
          const index = translation.inline.indexOf(value);
          if (index === -1) {
            errors.push(`Missing inline code in Chinese page: ${path.relative(docsRoot, source)}: ${value}`);
          } else {
            translation.inline.splice(index, 1);
          }
        }
      }
    }
  }
}
checkTranslations(docsRoot);

const examplesRoot = fileURLToPath(new URL('../../examples/', import.meta.url));
const examples = readdirSync(examplesRoot).filter((name) => name.endsWith('.yaml'));
for (const locale of ['', 'zh-cn']) {
  for (const name of examples) {
    const page = path.join(root, locale, 'examples', name.slice(0, -5), 'index.html');
    const pageData = pages.get(page);
    if (!pageData) {
      errors.push(`Missing example page: ${locale ? `${locale}/` : ''}${name}`);
      continue;
    }
    const { document } = pageData;
    // Expressive Code encodes line breaks as DEL in the copy button payload.
    const copied = document.querySelector('button[data-code]')?.getAttribute('data-code')?.replaceAll('\u007f', '\n');
    const source = readFileSync(path.join(examplesRoot, name), 'utf8').replaceAll('\r\n', '\n').trimEnd();
    if (copied?.trimEnd() !== source) errors.push(`Example copy payload differs from source: ${locale ? `${locale}/` : ''}${name}`);
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exitCode = 1;
} else {
  console.log(`Checked headers, internal links and anchors in ${files.length} HTML pages and copy payloads for ${examples.length} examples in both languages.`);
}
