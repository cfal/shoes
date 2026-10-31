const files = import.meta.glob<string>('../../../examples/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const examples = Object.entries(files)
  .map(([path, code]) => {
    const filename = path.split('/').at(-1)!;
    return { filename, slug: filename.slice(0, -5), code };
  })
  .sort((a, b) => a.filename.localeCompare(b.filename));
