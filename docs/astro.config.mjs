import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { sourceRef } from './metadata.mjs';

export default defineConfig({
  site: 'https://shoes-rs.github.io',
  base: '/',
  trailingSlash: 'always',
  integrations: [starlight({
    title: 'shoes',
    description: 'Configuration and operation of shoes',
    locales: {
      root: { label: 'English', lang: 'en' },
      'zh-cn': { label: '简体中文', lang: 'zh-CN' },
    },
    components: { SiteTitle: './src/components/SiteTitle.astro' },
    head: [{ tag: 'meta', attrs: { name: 'shoes-source-ref', content: sourceRef } }],
    sidebar: [
      { label: 'Start', translations: { 'zh-CN': '入门' }, items: ['index', 'start/installation', 'start/first-config', 'start/configuration-model', 'start/examples'] },
      { label: 'Configuration', translations: { 'zh-CN': '配置' }, items: ['config/server', 'config/client', 'config/tun', 'config/global-settings', 'config/quic-sockets'] },
      { label: 'Protocols', translations: { 'zh-CN': '协议' }, items: [{ autogenerate: { directory: 'protocols' } }] },
      { label: 'Routing', translations: { 'zh-CN': '路由' }, items: ['routing/rules', 'routing/remote-sources', 'routing/chains', 'routing/groups', 'routing/clash-controller'] },
      { label: 'DNS', items: ['dns/configuration', 'dns/native', 'dns/fake'] },
      { label: 'Security', translations: { 'zh-CN': '安全' }, items: ['security/certificates', 'security/named-pems', 'security/tls-key-exchange', 'security/mtls'] },
      { label: 'Operations', translations: { 'zh-CN': '运维' }, items: ['operations/cli', 'operations/reload', 'operations/tips'] },
    ],
  })],
});
