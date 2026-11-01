import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { sourceRef } from './metadata.mjs';

export default defineConfig({
  site: 'https://shoes-rs.github.io',
  base: '/',
  trailingSlash: 'always',
  integrations: [starlight({
    title: 'Shoes',
    description: 'Configuration and operation of Shoes',
    components: { SiteTitle: './src/components/SiteTitle.astro' },
    head: [{ tag: 'meta', attrs: { name: 'shoes-source-ref', content: sourceRef } }],
    sidebar: [
      { label: 'Start', items: ['index', 'start/installation', 'start/first-config', 'start/configuration-model', 'start/examples'] },
      { label: 'Configuration', items: ['config/server', 'config/client', 'config/tun', 'config/global-settings', 'config/quic-sockets'] },
      { label: 'Protocols', items: [{ autogenerate: { directory: 'protocols' } }] },
      { label: 'Routing', items: ['routing/rules', 'routing/remote-sources', 'routing/chains', 'routing/groups', 'routing/clash-controller'] },
      { label: 'DNS', items: ['dns/configuration', 'dns/native', 'dns/fake'] },
      { label: 'Security', items: ['security/certificates', 'security/named-pems', 'security/tls-key-exchange', 'security/mtls'] },
      { label: 'Operations', items: ['operations/cli', 'operations/reload', 'operations/tips'] },
    ],
  })],
});
