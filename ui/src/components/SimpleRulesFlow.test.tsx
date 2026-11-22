/*
 * Copyright 2026 Julien Bombled
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import '@testing-library/jest-dom/vitest';
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within
} from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { App } from '../App';
import { UI_CONFIG } from '../config/constants';
import { routewardClient } from '../services/ipc';
import { ThemeForgeProvider } from '../theme/ThemeForgeContext';
import {
  ProfileConfig,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  SystemApplicationEntry,
  TrackedConnection
} from '../types/routeward';
import { ConnectionsView } from './ConnectionsView';
import { ProxiesView } from './ProxiesView';
import { RulesView } from './RulesView';

const proxy = (id: string, overrides: Partial<ProxyNode> = {}): ProxyNode => ({
  id,
  name: `Proxy ${id}`,
  protocol: 'socks5',
  host: `${id}.example.com`,
  port: 1080,
  auth: null,
  udpEnabled: true,
  tls: false,
  sni: null,
  enabled: true,
  lastLatencyMs: null,
  exitIp: null,
  ...overrides
});

const rule = (overrides: Partial<RoutingRule>): RoutingRule => ({
  id: 'r',
  name: 'Rule',
  enabled: true,
  priority: 50,
  processPatterns: [],
  domainPatterns: [],
  ipCidrs: [],
  portRanges: [],
  protocol: 'any',
  action: { type: 'direct' },
  ...overrides
});

const rulesViewProps = (overrides: Record<string, unknown> = {}) => ({
  rules: [] as RoutingRule[],
  proxies: [] as ProxyNode[],
  chains: [] as ProxyChain[],
  experienceMode: 'simple' as const,
  osName: 'WINDOWS',
  onEvaluateRule: vi.fn(),
  onAddRule: vi.fn(),
  onToggleRule: vi.fn(),
  onReorderRule: vi.fn(),
  onRemoveRule: vi.fn(),
  ...overrides
});

const openSimpleModal = () => {
  fireEvent.click(
    screen.getByRole('button', { name: i18n.t('rules.simple.add_button') })
  );
  return within(screen.getByRole('dialog'));
};

describe('RulesView Simple entry points', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('turns a bare website into a wildcard that also covers www and subdomains', () => {
    const props = rulesViewProps();
    render(<RulesView {...props} />);
    const dialog = openSimpleModal();

    fireEvent.click(dialog.getByRole('button', { name: i18n.t('rules.simple.type_site') }));
    fireEvent.change(
      dialog.getByPlaceholderText(i18n.t('rules.simple.target_site_placeholder')),
      { target: { value: 'exemple.com' } }
    );
    expect(
      dialog.getByText(i18n.t('rules.simple.url_preview', { domain: 'exemple.com' }))
    ).toBeInTheDocument();
    fireEvent.click(
      dialog.getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    fireEvent.click(dialog.getByRole('button', { name: i18n.t('rules.modal.add.submit') }));

    const created = props.onAddRule.mock.calls[0][0] as RoutingRule;
    expect(created.domainPatterns).toEqual(['*.exemple.com']);
    expect(created.processPatterns).toEqual([]);
    expect(created.id).toBe('rule-site-exemple-com');
    expect(created.priority).toBe(UI_CONFIG.DEFAULT_SITE_RULE_PRIORITY);
  });

  it('completes an application name with .exe on Windows and warns when nothing running matches', async () => {
    const apps: SystemApplicationEntry[] = [
      { name: 'vlc.exe', executablePath: 'C:\\vlc.exe', running: true }
    ];
    const props = rulesViewProps({
      onListSystemApps: vi.fn().mockResolvedValue(apps)
    });
    render(<RulesView {...props} />);

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.simple.detected_apps_load') })
    );
    await screen.findByText('vlc.exe');

    const dialog = openSimpleModal();
    fireEvent.change(
      dialog.getByPlaceholderText(i18n.t('rules.simple.target_app_placeholder')),
      { target: { value: 'spotify' } }
    );
    expect(
      dialog.getByText(i18n.t('rules.simple.app_name_completed', { name: 'spotify.exe' }))
    ).toBeInTheDocument();
    expect(
      dialog.getByText(i18n.t('rules.simple.app_not_running_warning', { app: 'spotify.exe' }))
    ).toBeInTheDocument();

    fireEvent.click(dialog.getByRole('button', { name: i18n.t('rules.modal.add.submit') }));
    const created = props.onAddRule.mock.calls[0][0] as RoutingRule;
    expect(created.processPatterns).toEqual(['spotify.exe']);
    expect(created.id).toBe('rule-app-spotify-exe');
    expect(created.priority).toBe(UI_CONFIG.SIMPLE_APP_RULE_PRIORITY);
    expect(created.name).toBe('Spotify');
  });

  it('refuses to save a Simple rule without any app, site or address', () => {
    const props = rulesViewProps();
    render(<RulesView {...props} />);
    const dialog = openSimpleModal();

    fireEvent.change(
      dialog.getByPlaceholderText(i18n.t('rules.simple.target_app_placeholder')),
      { target: { value: '   ' } }
    );
    fireEvent.click(
      dialog.getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    fireEvent.submit(dialog.getByRole('button', { name: i18n.t('rules.modal.add.submit') }).closest('form')!);

    expect(dialog.getByRole('alert')).toHaveTextContent(
      i18n.t('rules.simple.error_no_criteria')
    );
    expect(props.onAddRule).not.toHaveBeenCalled();
  });

  it('copies the simple inputs into the advanced fields', () => {
    const props = rulesViewProps();
    render(<RulesView {...props} />);
    const dialog = openSimpleModal();

    fireEvent.change(
      dialog.getByPlaceholderText(i18n.t('rules.simple.target_app_placeholder')),
      { target: { value: 'spotify' } }
    );
    fireEvent.change(
      dialog.getByPlaceholderText(i18n.t('rules.simple.optional_site_placeholder')),
      { target: { value: 'exemple.com' } }
    );
    fireEvent.click(
      dialog.getByRole('button', { name: i18n.t('rules.simple.show_advanced_options') })
    );

    expect(dialog.getByLabelText(i18n.t('rules.modal.add.processes_label'))).toHaveValue(
      'spotify.exe'
    );
    expect(dialog.getByLabelText(i18n.t('rules.modal.add.domains_label'))).toHaveValue(
      '*.exemple.com'
    );
  });

  it('highlights the action that really applies and saves one deterministic rule per app', async () => {
    const category = rule({
      id: 'rule-visual-app-browsers',
      name: 'Browsers',
      priority: 18,
      processPatterns: ['firefox.exe'],
      action: { type: 'direct' }
    });
    const props = rulesViewProps({
      rules: [category],
      proxies: [proxy('p1')],
      onListSystemApps: vi
        .fn()
        .mockResolvedValue([
          { name: 'firefox.exe', executablePath: 'C:\\ff.exe', running: true }
        ])
    });
    const { rerender } = render(<RulesView {...props} />);
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.simple.detected_apps_load') })
    );
    await waitFor(() =>
      expect(document.getElementById('simple-detected-apps-search')).not.toBeNull()
    );
    const detectedList = document.getElementById('simple-detected-apps-search')!
      .parentElement as HTMLElement;
    const row = detectedList;
    expect(
      within(row).getByRole('button', { name: i18n.t('connections.simple.route_direct') })
    ).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(
      within(row).getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    const created = props.onAddRule.mock.calls[0][0] as RoutingRule;
    expect(created.id).toBe('rule-app-firefox-exe');
    expect(created.priority).toBeLessThan(category.priority);

    rerender(<RulesView {...props} rules={[category, created]} />);
    const rowAfter = document.getElementById('simple-detected-apps-search')!
      .parentElement as HTMLElement;
    expect(
      within(rowAfter).getByRole('button', {
        name: i18n.t('connections.simple.route_blocked')
      })
    ).toHaveAttribute('aria-pressed', 'true');
    expect(
      within(rowAfter).getByRole('button', {
        name: i18n.t('connections.simple.route_direct')
      })
    ).toHaveAttribute('aria-pressed', 'false');
  });

  it('splits the telemetry pack into one rule per criterion and drops non-executable names', () => {
    const props = rulesViewProps();
    render(<RulesView {...props} />);
    fireEvent.click(
      screen.getByRole('checkbox', { name: i18n.t('rules.simple.pack_telemetry_title') })
    );

    expect(props.onAddRule).toHaveBeenCalledTimes(2);
    const [byProcess, byDomain] = props.onAddRule.mock.calls.map(
      (call) => call[0] as RoutingRule
    );
    expect(byProcess.domainPatterns).toEqual([]);
    expect(byProcess.processPatterns).not.toContain('DiagTrack');
    expect(byProcess.processPatterns.length).toBeGreaterThan(0);
    expect(byDomain.processPatterns).toEqual([]);
    expect(byDomain.domainPatterns.length).toBeGreaterThan(0);
    expect(byProcess.id).not.toBe(byDomain.id);
  });

  it('checks both the bare host and its www variant in the site tester', async () => {
    const onEvaluateRule = vi.fn().mockResolvedValue({
      matchedRuleName: UI_CONFIG.ENGINE_DEFAULT_RULE_NAME,
      action: { type: 'direct' },
      resolvedFromFakeIp: false,
      effectiveDomain: null
    });
    const props = rulesViewProps({ onEvaluateRule });
    render(<RulesView {...props} />);
    fireEvent.change(
      screen.getByPlaceholderText(i18n.t('rules.simple.tester_placeholder')),
      { target: { value: 'exemple.com' } }
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.simple.tester_button') })
    );

    await waitFor(() => expect(onEvaluateRule).toHaveBeenCalledTimes(2));
    expect(onEvaluateRule.mock.calls.map((call) => call[0].targetHost)).toEqual([
      'exemple.com',
      'www.exemple.com'
    ]);
    expect(await screen.findByText('www.exemple.com')).toBeInTheDocument();
    expect(
      screen.getAllByText(
        i18n.t('rules.simple.tester_rule_label', {
          name: i18n.t('rules.generated.default_policy')
        })
      )
    ).toHaveLength(2);
  });
});

describe('ProxiesView beginner link and status handling', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  const renderProxies = (overrides: Record<string, unknown> = {}) => {
    const props = {
      proxies: [] as ProxyNode[],
      chains: [] as ProxyChain[],
      rules: [] as RoutingRule[],
      experienceMode: 'simple' as const,
      onTestProxy: vi.fn(),
      onTestAllProxies: vi.fn(),
      onAddProxy: vi.fn(),
      onImportUris: vi.fn(),
      onCopyUri: vi.fn(),
      onRemoveProxy: vi.fn(),
      onAddChain: vi.fn(),
      onRemoveChain: vi.fn(),
      onToggleSimpleFailover: vi.fn(),
      ...overrides
    };
    render(<ProxiesView {...props} />);
    return props;
  };

  const openAddModal = () => {
    fireEvent.click(screen.getByRole('button', { name: i18n.t('proxies.simple.add') }));
  };
  const field = (key: string) => screen.getByLabelText(i18n.t(key));

  it('parses the link on blur, defaults a scheme-less link to HTTP and keeps unreadable text', () => {
    renderProxies();
    openAddModal();
    const link = field('proxies.modal.add_proxy.quick_paste_label');

    fireEvent.change(link, { target: { value: 'not a link' } });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    fireEvent.blur(link);
    expect(screen.getByRole('alert')).toHaveTextContent(
      i18n.t('proxies.modal.add_proxy.quick_paste_invalid')
    );
    expect(link).toHaveValue('not a link');

    fireEvent.change(link, { target: { value: '1.2.3.4:8080' } });
    expect(field('proxies.modal.add_proxy.host_label')).toHaveValue('');
    fireEvent.keyDown(link, { key: 'Enter' });
    expect(field('proxies.modal.add_proxy.host_label')).toHaveValue('1.2.3.4');
    expect(field('proxies.modal.add_proxy.port_label')).toHaveValue(8080);
    expect(field('proxies.modal.add_proxy.protocol_label')).toHaveValue('http');
  });

  it('applies a pasted link immediately', () => {
    renderProxies();
    openAddModal();
    fireEvent.paste(field('proxies.modal.add_proxy.quick_paste_label'), {
      clipboardData: { getData: () => 'socks5://bob:pw@proxy.example.com:1081#Home' }
    });
    expect(field('proxies.modal.add_proxy.host_label')).toHaveValue('proxy.example.com');
    expect(field('proxies.modal.add_proxy.port_label')).toHaveValue(1081);
    expect(field('proxies.modal.add_proxy.name_label')).toHaveValue('Home');
  });

  it('splits host:port typed in the host field and follows the protocol default port', () => {
    const props = renderProxies();
    openAddModal();

    fireEvent.change(field('proxies.modal.add_proxy.protocol_label'), {
      target: { value: 'http' }
    });
    expect(field('proxies.modal.add_proxy.port_label')).toHaveValue(
      UI_CONFIG.DEFAULT_PROXY_PORT_BY_PROTOCOL.http
    );

    fireEvent.change(field('proxies.modal.add_proxy.name_label'), {
      target: { value: 'Office' }
    });
    const host = field('proxies.modal.add_proxy.host_label');
    fireEvent.change(host, { target: { value: '10.0.0.1:3128' } });
    expect(host).toHaveValue('10.0.0.1:3128');
    fireEvent.blur(host);
    expect(host).toHaveValue('10.0.0.1');
    expect(field('proxies.modal.add_proxy.port_label')).toHaveValue(3128);

    fireEvent.submit(host.closest('form')!);
    const saved = props.onAddProxy.mock.calls[0][0] as ProxyNode;
    expect(saved.host).toBe('10.0.0.1');
    expect(saved.port).toBe(3128);
    expect(saved.protocol).toBe('http');
  });

  it('lets the user reveal the password', () => {
    renderProxies();
    openAddModal();
    const password = screen.getByLabelText(i18n.t('proxies.modal.add_proxy.password_label'));
    expect(password).toHaveAttribute('type', 'password');
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.modal.add_proxy.show_password') })
    );
    expect(password).toHaveAttribute('type', 'text');
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.modal.add_proxy.hide_password') })
    );
    expect(password).toHaveAttribute('type', 'password');
  });

  it('shows "not responding" for a failed test and no jargon in Simple mode', () => {
    renderProxies({
      proxies: [proxy('p1', { lastLatencyMs: null }), proxy('p2', { lastLatencyMs: 20 })],
      unreachableProxyIds: ['p1']
    });
    expect(screen.getByText(i18n.t('proxies.simple.status_unreachable'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('proxies.simple.status_untested'))).not.toBeInTheDocument();
    expect(screen.queryByText('socks5')).not.toBeInTheDocument();
    expect(screen.queryByText(/ms\)/)).not.toBeInTheDocument();
  });

  it('warns in plain words about the apps that use a proxy before deleting it', () => {
    renderProxies({
      proxies: [proxy('p1'), proxy('p2')],
      rules: [rule({ id: 'a', action: { type: 'proxy', targetId: 'p1' } })]
    });
    fireEvent.click(
      screen.getAllByRole('button', { name: i18n.t('proxies.card.action.delete') })[0]
    );
    expect(
      screen.getByText(
        i18n.t('proxies.delete.warning_retarget', { count: 1, name: 'Proxy p2' })
      )
    ).toBeInTheDocument();
  });

  it('never adopts an Expert failover chain in the Simple failover toggle', () => {
    const expertChain: ProxyChain = {
      id: 'chain-expert',
      name: 'Expert',
      strategy: 'failover',
      proxyIds: ['p1', 'p2'],
      enabled: true
    };
    const props = renderProxies({
      proxies: [proxy('p1'), proxy('p2')],
      chains: [expertChain]
    });
    const toggle = screen.getByRole('checkbox', {
      name: i18n.t('proxies.simple.failover_title')
    });
    expect(toggle).not.toBeChecked();
    fireEvent.click(toggle);
    expect(props.onToggleSimpleFailover).toHaveBeenCalledTimes(1);
    expect(props.onToggleSimpleFailover.mock.calls[0][0]).toBe(true);
    expect(props.onToggleSimpleFailover.mock.calls[0][1].id).toBe(
      UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID
    );
  });
});

describe('ConnectionsView quick actions', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  const connection: TrackedConnection = {
    id: 'c1',
    pid: 7,
    processName: 'curl.exe',
    processPath: 'C:\\Windows\\curl.exe',
    targetHost: 'dual.example.org',
    resolvedDomain: 'dual.example.org',
    targetPort: 443,
    protocol: 'tcp',
    matchedRule: UI_CONFIG.ENGINE_DEFAULT_RULE_NAME,
    routeLabel: 'DIRECT',
    latencyMs: 10,
    rxBytes: 1,
    txBytes: 1,
    status: 'active',
    startedAt: '2026-11-15T08:00:00Z'
  };

  it('creates one deterministic application rule above category rules, replacing an older one', () => {
    const onQuickCreateRule = vi.fn();
    const { rerender } = render(
      <ConnectionsView
        connections={[connection]}
        proxies={[]}
        experienceMode="simple"
        onScanOsSockets={vi.fn()}
        onClearClosed={vi.fn()}
        onTerminateConnection={vi.fn()}
        onQuickCreateRule={onQuickCreateRule}
      />
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    const [first, second] = onQuickCreateRule.mock.calls.map((c) => c[0] as RoutingRule);
    expect(first.id).toBe('rule-app-curl-exe');
    expect(second.id).toBe(first.id);
    expect(first.priority).toBe(UI_CONFIG.SIMPLE_APP_RULE_PRIORITY);
    expect(first.name).toBe('cURL');

    const legacy = rule({
      id: 'rule-quick-old',
      priority: 8,
      processPatterns: ['curl.exe'],
      action: { type: 'direct' }
    });
    rerender(
      <ConnectionsView
        connections={[connection]}
        proxies={[]}
        rules={[legacy]}
        experienceMode="simple"
        onScanOsSockets={vi.fn()}
        onClearClosed={vi.fn()}
        onTerminateConnection={vi.fn()}
        onQuickCreateRule={onQuickCreateRule}
      />
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    expect(onQuickCreateRule.mock.calls[2][0].id).toBe('rule-quick-old');
    expect(onQuickCreateRule.mock.calls[2][0].priority).toBe(
      UI_CONFIG.SIMPLE_APP_RULE_PRIORITY
    );
  });

  it('localizes the generated site rule name and the engine fallback rule name', () => {
    const onQuickCreateRule = vi.fn();
    render(
      <ConnectionsView
        connections={[connection]}
        proxies={[]}
        experienceMode="expert"
        onScanOsSockets={vi.fn()}
        onClearClosed={vi.fn()}
        onTerminateConnection={vi.fn()}
        onQuickCreateRule={onQuickCreateRule}
      />
    );
    expect(screen.queryByText(UI_CONFIG.ENGINE_DEFAULT_RULE_NAME)).not.toBeInTheDocument();
    expect(screen.getByText(i18n.t('rules.generated.default_policy'))).toBeInTheDocument();

    fireEvent.click(screen.getByText('curl.exe'));
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('connections.inspector.drawer.block_domain') })
    );
    const created = onQuickCreateRule.mock.calls[0][0] as RoutingRule;
    expect(created.name).toBe(
      i18n.t('connections.quick.block_site', { domain: 'dual.example.org' })
    );
    expect(created.id).toBe('rule-site-dual-example-org');
  });
});

describe('App proxy lifecycle handlers', () => {
  let profile: ProfileConfig;
  let upsertRule: ReturnType<typeof vi.spyOn>;
  let removeProxy: ReturnType<typeof vi.spyOn>;
  let removeChain: ReturnType<typeof vi.spyOn>;
  let upsertProxy: ReturnType<typeof vi.spyOn>;
  let upsertChain: ReturnType<typeof vi.spyOn>;

  const renderProxyTab = (initial: Partial<ProfileConfig>) => {
    profile = { ...routewardClient.getProfile(), ...initial } as ProfileConfig;
    vi.spyOn(routewardClient, 'getProfile').mockImplementation(() => profile);
    render(
      <ThemeForgeProvider>
        <App />
      </ThemeForgeProvider>
    );
    fireEvent.keyDown(window, { key: '3', altKey: true });
  };

  beforeEach(() => {
    window.localStorage.clear();
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.EXPERIENCE_MODE, 'simple');
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED, 'true');
    vi.spyOn(routewardClient, 'startRealtimeStream').mockImplementation(() => {});
    vi.spyOn(routewardClient, 'getPacStatus').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'getAutostartStatus').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'getSystemProxyStatus').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'listNamedProfiles').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'getCurrentNetworkInfo').mockImplementation(
      () => new Promise(() => {})
    );
    vi.spyOn(routewardClient, 'getDiagnostics').mockReturnValue({
      daemonConnected: true,
      running: true,
      osName: 'WINDOWS',
      interceptionMode: 'hybrid',
      elevatedPrivileges: true,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr'
    });
    upsertRule = vi
      .spyOn(routewardClient, 'upsertRule')
      .mockImplementation(async () => profile);
    removeProxy = vi
      .spyOn(routewardClient, 'removeProxy')
      .mockImplementation(async () => profile);
    removeChain = vi
      .spyOn(routewardClient, 'removeChain')
      .mockImplementation(async () => profile);
    upsertProxy = vi
      .spyOn(routewardClient, 'upsertProxy')
      .mockImplementation(async () => profile);
    upsertChain = vi
      .spyOn(routewardClient, 'upsertChain')
      .mockImplementation(async () => profile);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  const confirmDelete = (index = 0) => {
    fireEvent.click(
      screen.getAllByRole('button', { name: i18n.t('proxies.card.action.delete') })[index]
    );
    fireEvent.click(
      screen.getByRole('button', {
        name: `${i18n.t('app.confirm_delete.confirm')}: ${i18n.t('proxies.card.action.delete')}`
      })
    );
  };

  it('moves rules to the new primary proxy when a proxy is deleted', async () => {
    renderProxyTab({
      proxies: [proxy('p1'), proxy('p2')],
      chains: [],
      rules: [
        rule({ id: 'rule-app-x', action: { type: 'proxy', targetId: 'p1' } }),
        rule({ id: 'unrelated', action: { type: 'proxy', targetId: 'p2' } })
      ]
    });
    confirmDelete(0);

    await waitFor(() => expect(removeProxy).toHaveBeenCalledWith('p1'));
    expect(upsertRule).toHaveBeenCalledTimes(1);
    expect(upsertRule.mock.calls[0][0]).toMatchObject({
      id: 'rule-app-x',
      enabled: true,
      action: { type: 'proxy', targetId: 'p2' }
    });
    expect(
      await screen.findByText(
        i18n.t('proxies.delete.toast_retargeted', { count: 1, name: 'Proxy p2' })
      )
    ).toBeInTheDocument();
  });

  it('turns rules off, never to direct, when the last proxy is deleted, and warns that the password is lost on undo', async () => {
    renderProxyTab({
      proxies: [proxy('p1', { auth: { username: 'bob', hasPassword: true } })],
      chains: [],
      rules: [rule({ id: 'rule-app-x', action: { type: 'proxy', targetId: 'p1' } })]
    });
    confirmDelete(0);

    await waitFor(() => expect(removeProxy).toHaveBeenCalledWith('p1'));
    expect(upsertRule.mock.calls[0][0]).toMatchObject({
      id: 'rule-app-x',
      enabled: false,
      action: { type: 'proxy', targetId: 'p1' }
    });
    expect(
      await screen.findByText(i18n.t('proxies.delete.toast_disabled', { count: 1 }))
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: i18n.t('app.toast.undo') }));
    await waitFor(() => expect(upsertProxy).toHaveBeenCalledTimes(1));
    expect(upsertProxy.mock.calls[0][0]).toMatchObject({
      id: 'p1',
      auth: { username: 'bob', hasPassword: false }
    });
    expect(upsertRule.mock.calls[1][0]).toMatchObject({ id: 'rule-app-x', enabled: true });
    expect(
      await screen.findByText(i18n.t('proxies.delete.undo_password_needed'))
    ).toBeInTheDocument();
  });

  it('retargets only Simple rules when making another proxy primary', async () => {
    renderProxyTab({
      proxies: [proxy('p1'), proxy('p2')],
      chains: [],
      rules: [
        rule({ id: 'rule-app-x', action: { type: 'proxy', targetId: 'p1' } }),
        rule({ id: 'rule-quick-1', action: { type: 'proxy', targetId: 'p1' } }),
        rule({ id: 'expert-rule', action: { type: 'proxy', targetId: 'p1' } })
      ]
    });
    vi.spyOn(routewardClient, 'setPrimaryProxy').mockImplementation(async () => {
      profile = { ...profile, proxies: [profile.proxies[1], profile.proxies[0]] };
      return profile;
    });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('proxies.simple.set_primary') }));

    await waitFor(() => expect(upsertRule).toHaveBeenCalledTimes(2));
    expect(
      (upsertRule.mock.calls as unknown[][]).map((call) => (call[0] as RoutingRule).id).sort()
    ).toEqual([
      'rule-app-x',
      'rule-quick-1'
    ]);
    for (const call of upsertRule.mock.calls as unknown[][]) {
      expect((call[0] as RoutingRule).action).toEqual({ type: 'proxy', targetId: 'p2' });
    }
  });

  it('manages only its own failover chain and only Simple rules', async () => {
    const expertChain: ProxyChain = {
      id: 'chain-expert',
      name: 'Expert',
      strategy: 'failover',
      proxyIds: ['p1', 'p2'],
      enabled: true
    };
    renderProxyTab({
      proxies: [proxy('p1'), proxy('p2')],
      chains: [expertChain],
      rules: [
        rule({ id: 'rule-app-x', action: { type: 'proxy', targetId: 'p1' } }),
        rule({ id: 'expert-rule', action: { type: 'proxy', targetId: 'p1' } })
      ]
    });
    fireEvent.click(
      screen.getByRole('checkbox', { name: i18n.t('proxies.simple.failover_title') })
    );

    await waitFor(() => expect(upsertChain).toHaveBeenCalledTimes(1));
    expect(upsertChain.mock.calls[0][0]).toMatchObject({
      id: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID
    });
    await waitFor(() => expect(upsertRule).toHaveBeenCalledTimes(1));
    expect(upsertRule.mock.calls[0][0]).toMatchObject({
      id: 'rule-app-x',
      action: { type: 'chain', targetId: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID }
    });
    expect(removeChain).not.toHaveBeenCalled();
  });
});
