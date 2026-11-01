# Shoes documentation

This Starlight project is the source for `https://shoes-rs.github.io/`. Documentation is authored with Shoes, not copied into the publication repository. The publication workflow resolves an exact Shoes commit, runs `npm ci` and `npm run check` here, then deploys `docs/dist/` to GitHub Pages. The site repository owns source selection and publication; this repository owns the content. Development publication follows successful documentation CI on master, with a pinned-commit override available in the site repository.

## Local development

Use Node 24 (see `.node-version`):

```sh
cd docs
npm ci
npm run dev
npm run check
```

`npm run build` writes `docs/dist/`. `npm run check` builds the site, checks internal page and heading links (including links from README, CHANGELOG, and CONFIG), and compares every example's copy-button payload with its YAML source. These checks do not fetch external URLs or validate a running Shoes process. Rust CI separately parses all tracked YAML examples and fully validates a curated subset through the native configuration pipeline. `npm run preview` serves the built site, including its search index. Development and preview servers bind to all interfaces for VM access; use them only on a trusted network. For loopback-only access, run `npm exec -- astro dev --host 127.0.0.1` (or replace `dev` with `preview`).

`SHOES_DOCS_REF` is the full lowercase Shoes commit SHA shown on every page and in page metadata; an invalid explicit value fails the build. Without it, the build uses the local Git revision; links describe that committed revision, not uncommitted edits. If no revision is available, source links are omitted. `SHOES_DOCS_LABEL` is an explicit publication label, for example `1.2.0` or `dev`. Without it, all builds are labeled **dev** (unreleased). Do not infer release status from `Cargo.toml`.

For now, `/` contains only development documentation, without a version selector. Start versioned documentation with the first release containing buildable docs: keep release builds pinned, put development builds under `/dev/`, and publish all retained versions in one Pages artifact. That requires base-aware links and isolated search indexes before enabling a selector. Do not relabel current documentation as an older release; earlier releases require a reviewed documentation backport.

## Authoring contract

- Keep new configuration guidance beside the parser/validator change in one Shoes PR. `CONFIG.md` is an entry index, not a second reference.
- Use one page per protocol under `src/content/docs/protocols/`, with separate server and client sections where supported. Put shared fields in `config/`, routing in `routing/`, and operational behavior in `operations/`. Link rather than duplicate.
- Lead with a usable example. For complete files, import tracked `../examples/*.yaml` as raw text into Starlight's `Code` component, as in `first-config.mdx`. These snippets have copy buttons and are compiled from the same source that CI checks. Keep ordinary explanations in `.md`; use `.mdx` only for imports or components.
- Mark schema sketches and partial fragments as illustrative, not runnable. Document accepted values, requiredness, omission/default behavior, units, constraints, and client/server differences. Do not put real credentials in tracked examples.
- Extend the native example tests when a new complete example can be validated without external services. Do not treat parsing alone as runtime validation; certificates, routes, sockets, and platform support may still fail.
- Keep dependencies exact in `package.json` and commit `package-lock.json`. Introduce generated field reference or JSON Schema only after a scoped pilot accounts for custom deserializers and runtime defaults. The Rust validator remains authoritative.

Example pages and the catalog are generated from `examples/*.yaml` by one shared
Starlight page template. Adding a tracked YAML example automatically adds its
copyable page; do not add a second Markdown copy. Use `/examples/filename/`
(without `.yaml`) to link to it. The header shows the documentation label, source
revision, and GitHub repository link on every page, including mobile layouts.

The original `CONFIG.md` reference was separated by topic without changing its field semantics. When editing a page, check the corresponding `src/config` type and validator; a rendered reference is not proof that a setting still exists.
