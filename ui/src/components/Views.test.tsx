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
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { formatProxyUri, parseSingleProxyUri } from '../services/uri';
import { ConnectionsView } from './ConnectionsView';
import { DashboardView } from './DashboardView';
import { DnsView } from './DnsView';
import { ProxiesView } from './ProxiesView';
import { RulesView } from './RulesView';
import { SettingsView } from './SettingsView';
import {
  FakeIpEntry,
  LogEntry,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  SecurityPolicyConfig,
  SystemDiagnostics,
  TelemetrySnapshot,
  TrackedConnection
} from '../types/routeward';

describe('Core UI view components', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('RulesView toggles, reorders, and removes routing rules', () => {
    const rules: RoutingRule[] = [
      {
        id: 'rule-1',
        name: 'Browser via Proxy',
        enabled: true,
        priority: 10,
        processPatterns: ['firefox.exe'],
        domainPatterns: ['*.example.org'],
        ipCidrs: [],
        portRanges: [{ start: 443, end: 443 }],
        protocol: 'tcp',
        action: { type: 'proxy', targetId: 'p1' }
      },
      {
        id: 'rule-2',
        name: 'LAN Direct',
        enabled: true,
        priority: 20,
        processPatterns: [],
        domainPatterns: [],
        ipCidrs: ['10.0.0.0/8'],
        portRanges: [],
        protocol: 'any',
        action: { type: 'direct' }
      }
    ];
    const onToggleRule = vi.fn();
    const onReorderRule = vi.fn();
    const onRemoveRule = vi.fn();

    render(
      <RulesView
        rules={rules}
        proxies={[]}
        chains={[]}
        experienceMode="expert"
        onEvaluateRule={vi.fn().mockResolvedValue(null)}
        onAddRule={vi.fn()}
        onToggleRule={onToggleRule}
        onReorderRule={onReorderRule}
        onRemoveRule={onRemoveRule}
      />
    );

    expect(screen.getByText('Browser via Proxy')).toBeInTheDocument();
    expect(screen.getByText('LAN Direct')).toBeInTheDocument();

    const checkbox = screen.getByRole('checkbox', {
      name: `${i18n.t('rules.table.enabled.toggle_aria')}: Browser via Proxy`
    });
    fireEvent.click(checkbox);
    expect(onToggleRule).toHaveBeenCalledWith('rule-1');

    const moveDownBtn = screen.getByRole('button', {
      name: `${i18n.t('rules.table.controls.move_down')}: Browser via Proxy`
    });
    fireEvent.click(moveDownBtn);
    expect(onReorderRule).toHaveBeenCalledWith('rule-1', 'down');

    const deleteBtn = screen.getByRole('button', {
      name: `${i18n.t('rules.table.controls.delete')}: LAN Direct`
    });
    fireEvent.click(deleteBtn);
    expect(onRemoveRule).toHaveBeenCalledWith('rule-2');
  });

  it('RulesView edits an existing rule preserving id, priority, ports, and protocol', () => {
    const existingRule: RoutingRule = {
      id: 'rule-edit-1',
      name: 'Browser via Proxy',
      enabled: true,
      priority: 15,
      processPatterns: ['firefox.exe'],
      domainPatterns: ['*.example.org'],
      ipCidrs: [],
      portRanges: [{ start: 443, end: 443 }],
      protocol: 'tcp',
      action: { type: 'proxy', targetId: 'p1' }
    };
    const onAddRule = vi.fn();

    render(
      <RulesView
        rules={[existingRule]}
        proxies={[
          {
            id: 'p1',
            name: 'Primary Proxy',
            protocol: 'socks5',
            host: '127.0.0.1',
            port: 1080,
            auth: null,
            udpEnabled: true,
            tls: false,
            sni: null,
            enabled: true,
            lastLatencyMs: null,
            exitIp: null
          }
        ]}
        chains={[]}
        experienceMode="simple"
        onEvaluateRule={vi.fn().mockResolvedValue(null)}
        onAddRule={onAddRule}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
      />
    );

    const editBtn = screen.getByRole('button', {
      name: `${i18n.t('rules.table.controls.edit')}: Browser via Proxy`
    });
    fireEvent.click(editBtn);

    expect(
      screen.getByText(i18n.t('rules.modal.add.edit_title'))
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.modal.add.submit') })
    );

    expect(onAddRule).toHaveBeenCalledTimes(1);
    expect(onAddRule.mock.calls[0][0]).toEqual(existingRule);
  });

  it('ProxiesView triggers single proxy test, copy URI, batch URI import, and chain delete', async () => {
    const proxies: ProxyNode[] = [
      {
        id: 'p1',
        name: 'Frankfurt SOCKS5',
        protocol: 'socks5',
        host: '2001:db8::1',
        port: 1080,
        auth: null,
        udpEnabled: true,
        tls: false,
        sni: null,
        enabled: true,
        lastLatencyMs: 24,
        exitIp: '2001:db8::2'
      }
    ];
    const chains: ProxyChain[] = [
      {
        id: 'c1',
        name: 'Primary Chain',
        strategy: 'sequence',
        proxyIds: ['p1'],
        enabled: true
      }
    ];
    const onTestProxy = vi.fn().mockResolvedValue(undefined);
    const onImportUris = vi.fn();
    const onCopyUri = vi.fn();
    const onRemoveChain = vi.fn();

    render(
      <ProxiesView
        proxies={proxies}
        chains={chains}
        onTestProxy={onTestProxy}
        onTestAllProxies={vi.fn().mockResolvedValue(undefined)}
        onAddProxy={vi.fn()}
        onImportUris={onImportUris}
        onCopyUri={onCopyUri}
        onRemoveProxy={vi.fn()}
        onAddChain={vi.fn()}
        onRemoveChain={onRemoveChain}
      />
    );

    expect(screen.getByText('2001:db8::1:1080')).toBeInTheDocument();
    expect(screen.getByText(i18n.t('proxies.simple.active_badge'))).toBeInTheDocument();
    expect(screen.getByText('Primary Chain')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: i18n.t('proxies.card.action.test') }));
    await waitFor(() => expect(onTestProxy).toHaveBeenCalledWith('p1'));

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.card.action.copy_uri') })
    );
    expect(onCopyUri).toHaveBeenCalledWith(
      'socks5://[2001:db8::1]:1080#Frankfurt%20SOCKS5'
    );

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.section.servers.import_uri') })
    );
    const textarea = screen.getByRole('textbox', {
      name: i18n.t('proxies.modal.import_uri.title')
    });
    fireEvent.change(textarea, {
      target: { value: 'socks5://[::1]:1080#LocalV6' }
    });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.modal.import_uri.submit') })
    );
    expect(onImportUris).toHaveBeenCalledWith('socks5://[::1]:1080#LocalV6');

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.section.chains.delete') })
    );
    expect(onRemoveChain).toHaveBeenCalledWith('c1');
  });

  it('DnsView renders entries, allocates Fake-IP for domain, and flushes cache', () => {
    const entries: FakeIpEntry[] = [
      {
        fakeIp: '198.18.0.10',
        domain: 'api.example.com',
        hits: 3,
        expiresAt: '2026-11-15T09:00:00Z',
        ttlRemainingSeconds: 295
      }
    ];
    const onAllocate = vi.fn();
    const onFlush = vi.fn();

    render(<DnsView entries={entries} onAllocate={onAllocate} onFlush={onFlush} />);

    expect(screen.getByText('198.18.0.10')).toBeInTheDocument();
    expect(screen.getByText('api.example.com')).toBeInTheDocument();

    const input = screen.getByPlaceholderText(i18n.t('dns.allocate.placeholder'));
    fireEvent.change(input, { target: { value: '  service.internal  ' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('dns.allocate.submit') }));
    expect(onAllocate).toHaveBeenCalledWith('service.internal');

    fireEvent.click(screen.getByRole('button', { name: i18n.t('dns.header.flush_button') }));
    expect(onFlush).toHaveBeenCalledTimes(1);
  });

  it('ConnectionsView filters rows, opens inspector drawer, and creates quick rules or terminates socket', () => {
    const connections: TrackedConnection[] = [
      {
        id: 'c-active',
        pid: 4242,
        processName: 'curl.exe',
        processPath: 'C:\\Windows\\System32\\curl.exe',
        targetHost: '2001:db8::42',
        resolvedDomain: 'dual.example.org',
        targetPort: 443,
        protocol: 'tcp',
        matchedRule: 'Default',
        routeLabel: 'DIRECT',
        latencyMs: 14,
        rxBytes: 512,
        txBytes: 256,
        status: 'active',
        startedAt: '2026-11-15T08:10:00Z'
      },
      {
        id: 'c-blocked',
        pid: 9999,
        processName: 'tracker.exe',
        processPath: 'C:\\Temp\\tracker.exe',
        targetHost: 'telemetry.bad',
        resolvedDomain: 'telemetry.bad',
        targetPort: 443,
        protocol: 'udp',
        matchedRule: 'BlockQuic',
        routeLabel: 'BLOCKED',
        latencyMs: 0,
        rxBytes: 0,
        txBytes: 0,
        status: 'blocked',
        startedAt: '2026-11-15T08:10:05Z'
      }
    ];
    const onTerminateConnection = vi.fn();
    const onQuickCreateRule = vi.fn();

    render(
      <ConnectionsView
        connections={connections}
        proxies={[]}
        onScanOsSockets={vi.fn()}
        onClearClosed={vi.fn()}
        onTerminateConnection={onTerminateConnection}
        onQuickCreateRule={onQuickCreateRule}
      />
    );

    const searchInput = screen.getByPlaceholderText(
      i18n.t('connections.toolbar.search.placeholder')
    );
    fireEvent.change(searchInput, { target: { value: 'dual.example.org' } });
    expect(screen.getByText('curl.exe')).toBeInTheDocument();
    expect(screen.queryByText('tracker.exe')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('curl.exe'));
    expect(
      screen.getByText(i18n.t('connections.inspector.drawer.title'))
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', {
        name: i18n.t('connections.inspector.drawer.block_process')
      })
    );
    expect(onQuickCreateRule).toHaveBeenCalledTimes(1);
    expect(onQuickCreateRule.mock.calls[0][0].processPatterns).toEqual(['curl.exe']);
    expect(onQuickCreateRule.mock.calls[0][0].action).toEqual({ type: 'block' });

    fireEvent.click(
      screen.getByRole('button', {
        name: i18n.t('connections.inspector.drawer.terminate_socket')
      })
    );
    expect(onTerminateConnection).toHaveBeenCalledWith('c-active');
  });

  it('DashboardView simple mode renders use-case cards and triggers one-click scenario', () => {
    const telemetry: TelemetrySnapshot = {
      activeConnections: 4,
      downloadBytesPerSec: 1200,
      uploadBytesPerSec: 400,
      totalRxBytes: 2048,
      totalTxBytes: 1024,
      proxiedCount: 3,
      directCount: 1,
      blockedCount: 2,
      bandwidthHistory: [],
      topTalkers: []
    };
    const diagnostics: SystemDiagnostics = {
      daemonConnected: true,
      running: true,
      osName: 'Windows 11',
      interceptionMode: 'hybrid',
      elevatedPrivileges: true,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:10853',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr'
    };
    const securityPolicy: SecurityPolicyConfig = {
      killSwitchEnabled: true,
      blockUdpOnTcpOnlyProxy: true,
      strictDnsNoLocalFallback: true
    };
    const onApplyUseCase = vi.fn();

    render(
      <DashboardView
        telemetry={telemetry}
        diagnostics={diagnostics}
        dnsCount={5}
        securityPolicy={securityPolicy}
        experienceMode="simple"
        onApplyUseCase={onApplyUseCase}
        onUpdateSecurityPolicy={vi.fn()}
        onOpenWizard={vi.fn()}
        onNavigateRules={vi.fn()}
        onSwitchToExpert={vi.fn()}
      />
    );

    fireEvent.click(screen.getByText(i18n.t('dashboard.simple.uc_privacy_title')));
    expect(onApplyUseCase).toHaveBeenCalledWith('privacy');
  });

  it('RulesView simple mode hides priority table and creates rule from simple modal', () => {
    const onAddRule = vi.fn();
    render(
      <RulesView
        rules={[
          {
            id: 'r1',
            name: 'Firefox',
            enabled: true,
            priority: 10,
            processPatterns: ['firefox.exe'],
            domainPatterns: [],
            ipCidrs: [],
            portRanges: [],
            protocol: 'any',
            action: { type: 'proxy', targetId: 'p1' }
          }
        ]}
        proxies={[]}
        chains={[]}
        experienceMode="simple"
        onEvaluateRule={vi.fn()}
        onAddRule={onAddRule}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
      />
    );

    expect(
      screen.queryByRole('button', { name: i18n.t('rules.header.presets_button') })
    ).not.toBeInTheDocument();
    expect(screen.queryByText('#10')).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.simple.add_button') })
    );

    const targetInput = screen.getByPlaceholderText(
      i18n.t('rules.simple.target_app_placeholder')
    );
    fireEvent.change(targetInput, { target: { value: 'spotify.exe' } });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('connections.simple.route_direct') })
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.modal.add.submit') })
    );

    expect(onAddRule).toHaveBeenCalledTimes(1);
    expect(onAddRule.mock.calls[0][0].processPatterns).toEqual(['spotify.exe']);
    expect(onAddRule.mock.calls[0][0].action).toEqual({ type: 'direct' });
  });

  it('ProxiesView and ConnectionsView adapt cleanly to simple mode', () => {
    const onQuickCreateRule = vi.fn();
    render(
      <>
        <ProxiesView
          proxies={[]}
          chains={[]}
          experienceMode="simple"
          onTestProxy={vi.fn()}
          onTestAllProxies={vi.fn()}
          onAddProxy={vi.fn()}
          onImportUris={vi.fn()}
          onCopyUri={vi.fn()}
          onRemoveProxy={vi.fn()}
          onAddChain={vi.fn()}
          onRemoveChain={vi.fn()}
        />
        <ConnectionsView
          connections={[
            {
              id: 'c1',
              pid: 100,
              processName: 'firefox.exe',
              processPath: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
              targetHost: 'example.com',
              resolvedDomain: 'example.com',
              targetPort: 443,
              protocol: 'tcp',
              matchedRule: 'Browsers',
              routeLabel: 'PROXY',
              latencyMs: 25,
              rxBytes: 100,
              txBytes: 50,
              status: 'active',
              startedAt: '2026-11-15T08:00:00Z'
            },
            {
              id: 'c2',
              pid: 100,
              processName: 'firefox.exe',
              processPath: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
              targetHost: 'mozilla.org',
              resolvedDomain: 'mozilla.org',
              targetPort: 443,
              protocol: 'tcp',
              matchedRule: 'Browsers',
              routeLabel: 'PROXY',
              latencyMs: 30,
              rxBytes: 200,
              txBytes: 100,
              status: 'active',
              startedAt: '2026-11-15T08:01:00Z'
            }
          ]}
          proxies={[]}
          experienceMode="simple"
          onScanOsSockets={vi.fn()}
          onClearClosed={vi.fn()}
          onTerminateConnection={vi.fn()}
          onQuickCreateRule={onQuickCreateRule}
        />
      </>
    );

    expect(
      screen.queryByRole('button', { name: i18n.t('proxies.section.servers.test_all') })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(i18n.t('proxies.section.chains.title'))
    ).not.toBeInTheDocument();

    expect(screen.getAllByText('firefox.exe')).toHaveLength(1);
    expect(
      screen.getByText(`2 ${i18n.t('connections.simple.count_connections')}`)
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('connections.simple.route_blocked') })
    );
    expect(onQuickCreateRule).toHaveBeenCalledTimes(1);
    expect(onQuickCreateRule.mock.calls[0][0].processPatterns).toEqual(['firefox.exe']);
    expect(onQuickCreateRule.mock.calls[0][0].action).toEqual({ type: 'block' });
  });

  it('SettingsView manages language, unified anti-leak shield, and expert diagnostics subtabs', () => {
    const diagnostics: SystemDiagnostics = {
      daemonConnected: true,
      running: true,
      osName: 'Windows 11',
      interceptionMode: 'hybrid',
      elevatedPrivileges: true,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:10853',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'fr'
    };
    const logs: LogEntry[] = [
      {
        id: 'l1',
        timestamp: '2026-11-15T09:00:00Z',
        level: 'INFO',
        component: 'relay',
        message: 'Relay listening'
      }
    ];
    const onUpdateSecurityPolicy = vi.fn();
    const onToggleLanguage = vi.fn();

    const { rerender } = render(
      <SettingsView
        diagnostics={diagnostics}
        securityPolicy={{
          killSwitchEnabled: true,
          blockUdpOnTcpOnlyProxy: true,
          strictDnsNoLocalFallback: true,
          blockQuicUdp443: true,
          blockEncryptedDnsBypass: true
        }}
        experienceMode="simple"
        systemProxyEnabled={false}
        fakeIps={[]}
        logs={logs}
        activePaletteDisplayName="Dracula"
        activeAccent="Default"
        language="fr"
        onUpdateSecurityPolicy={onUpdateSecurityPolicy}
        onSetInterceptionMode={vi.fn()}
        onToggleSystemProxy={vi.fn().mockResolvedValue(undefined)}
        onOpenThemeForge={vi.fn()}
        onToggleLanguage={onToggleLanguage}
        onOpenWizard={vi.fn()}
        onOpenGlossary={vi.fn()}
        onOpenLauncher={vi.fn()}
        onImportProfile={vi.fn()}
        onExportProfile={vi.fn()}
        onAllocateDns={vi.fn()}
        onFlushDns={vi.fn()}
        onClearLogs={vi.fn()}
      />
    );

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('app.header.language.en') })
    );
    expect(onToggleLanguage).toHaveBeenCalledWith('en');

    fireEvent.click(
      screen.getByLabelText(i18n.t('settings.security.simple_shield_title'))
    );
    expect(onUpdateSecurityPolicy).toHaveBeenCalledWith({
      killSwitchEnabled: false,
      blockUdpOnTcpOnlyProxy: false,
      strictDnsNoLocalFallback: false,
      blockQuicUdp443: false,
      blockEncryptedDnsBypass: false
    });

    rerender(
      <SettingsView
        diagnostics={diagnostics}
        securityPolicy={{
          killSwitchEnabled: true,
          blockUdpOnTcpOnlyProxy: true,
          strictDnsNoLocalFallback: true
        }}
        experienceMode="expert"
        systemProxyEnabled={false}
        fakeIps={[
          {
            fakeIp: '198.18.0.5',
            domain: 'test.internal',
            hits: 1,
            expiresAt: '2026-11-15T10:00:00Z',
            ttlRemainingSeconds: 300
          }
        ]}
        logs={logs}
        activePaletteDisplayName="Dracula"
        activeAccent="Default"
        language="fr"
        onUpdateSecurityPolicy={onUpdateSecurityPolicy}
        onSetInterceptionMode={vi.fn()}
        onToggleSystemProxy={vi.fn().mockResolvedValue(undefined)}
        onOpenThemeForge={vi.fn()}
        onToggleLanguage={onToggleLanguage}
        onOpenWizard={vi.fn()}
        onOpenGlossary={vi.fn()}
        onOpenLauncher={vi.fn()}
        onImportProfile={vi.fn()}
        onExportProfile={vi.fn()}
        onAllocateDns={vi.fn()}
        onFlushDns={vi.fn()}
        onClearLogs={vi.fn()}
      />
    );

    fireEvent.click(
      screen.getByRole('button', {
        name: new RegExp(i18n.t('settings.diagnostics.subtab_dns'))
      })
    );
    expect(screen.getByText('198.18.0.5')).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole('button', {
        name: new RegExp(i18n.t('settings.diagnostics.subtab_logs'))
      })
    );
    expect(screen.getByText('Relay listening')).toBeInTheDocument();
  });

  it('supports socks4 & insecure URIs, FoxyProxy import, Apps Picker, errorDetail inspector, and PAC/Autostart/Named Profiles', async () => {
    const parsedSocks4 = parseSingleProxyUri('socks4://127.0.0.1:1080#LegacySocks');
    expect(parsedSocks4?.protocol).toBe('socks4');
    expect(parsedSocks4?.udpEnabled).toBe(false);

    const parsedHttpsInsecure = parseSingleProxyUri(
      'https://alice:secret@proxy.example.com:8443?sni=cdn.example.com&insecure=1#LabHttps'
    );
    expect(parsedHttpsInsecure?.tls).toBe(true);
    expect(parsedHttpsInsecure?.tlsSkipVerify).toBe(true);
    expect(formatProxyUri(parsedHttpsInsecure!)).toContain('insecure=1');

    const parsedRustTlsSkip = parseSingleProxyUri(
      'https://proxy.example.com:8443?tlsSkipVerify=1#RustUri'
    );
    expect(parsedRustTlsSkip?.tls).toBe(true);
    expect(parsedRustTlsSkip?.tlsSkipVerify).toBe(true);

    const onImportFoxy = vi.fn().mockResolvedValue({
      proxies: [],
      rules: [],
      skippedEntries: 0
    });
    const onListApps = vi.fn().mockResolvedValue([
      { name: 'msedge.exe', executablePath: 'C:\\Edge\\msedge.exe', running: true }
    ]);

    render(
      <RulesView
        rules={[]}
        proxies={[parsedHttpsInsecure!]}
        chains={[]}
        experienceMode="expert"
        onEvaluateRule={vi.fn()}
        onAddRule={vi.fn()}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
        onImportFoxyProxy={onImportFoxy}
        onListSystemApps={onListApps}
      />
    );

    expect(screen.getByText(i18n.t('rules.header.import_foxyproxy'))).toBeInTheDocument();
    fireEvent.click(screen.getByText(i18n.t('rules.header.import_foxyproxy')));
    fireEvent.change(
      screen.getByPlaceholderText(i18n.t('rules.modal.foxyproxy.json_placeholder')),
      { target: { value: '{"data":[{"title":"Edge","type":"socks5","hostname":"127.0.0.1","port":1080}]}' } }
    );
    fireEvent.click(screen.getByText(i18n.t('rules.modal.foxyproxy.submit')));
    await waitFor(() => {
      expect(onImportFoxy).toHaveBeenCalledWith(
        '{"data":[{"title":"Edge","type":"socks5","hostname":"127.0.0.1","port":1080}]}',
        ['msedge.exe']
      );
    });

    fireEvent.click(screen.getByText(i18n.t('rules.header.add_button')));
    fireEvent.click(screen.getByText(i18n.t('rules.modal.add.pick_app')));
    await waitFor(() => {
      expect(screen.getByText('msedge.exe')).toBeInTheDocument();
    });

    cleanup();

    const blockedConn: TrackedConnection = {
      id: 'c-err-1',
      pid: 4242,
      processName: 'msedge.exe',
      processPath: 'C:\\Edge\\msedge.exe',
      targetHost: 'blocked.example.com',
      resolvedDomain: 'blocked.example.com',
      targetPort: 443,
      protocol: 'tcp',
      matchedRule: 'Edge Rule',
      routeLabel: 'BLOCK',
      latencyMs: 12,
      rxBytes: 0,
      txBytes: 0,
      status: 'blocked',
      startedAt: '2026-11-15T12:00:00Z',
      errorDetail: 'Kill-switch blocked connection: upstream auth rejected'
    };

    render(
      <ConnectionsView
        connections={[blockedConn]}
        proxies={[parsedHttpsInsecure!]}
        experienceMode="expert"
        onScanOsSockets={vi.fn()}
        onClearClosed={vi.fn()}
        onTerminateConnection={vi.fn()}
        onQuickCreateRule={vi.fn()}
      />
    );
    fireEvent.click(screen.getByText('msedge.exe'));
    expect(
      screen.getByText('Kill-switch blocked connection: upstream auth rejected')
    ).toBeInTheDocument();
    expect(screen.getByText(i18n.t('connections.toolbar.export_csv'))).toBeInTheDocument();

    cleanup();

    const onTogglePac = vi.fn().mockResolvedValue(undefined);
    const onToggleAutostart = vi.fn().mockResolvedValue(undefined);
    const onSwitchNamedProfile = vi.fn().mockResolvedValue(undefined);

    render(
      <SettingsView
        diagnostics={{
          daemonConnected: true,
          running: true,
          osName: 'WINDOWS',
          interceptionMode: 'hybrid',
          elevatedPrivileges: true,
          relayTcpEndpoint: '127.0.0.1:10808',
          relayHttpEndpoint: '127.0.0.1:10809',
          dnsEndpoint: '127.0.0.1:1053',
          fakeIpCidr: '198.18.0.0/15',
          activeLocale: 'en'
        }}
        securityPolicy={{
          killSwitchEnabled: true,
          blockUdpOnTcpOnlyProxy: true,
          strictDnsNoLocalFallback: true
        }}
        experienceMode="expert"
        systemProxyEnabled={false}
        fakeIps={[]}
        logs={[]}
        activePaletteDisplayName="Drakul"
        activeAccent="Default"
        language="en"
        onUpdateSecurityPolicy={vi.fn()}
        onSetInterceptionMode={vi.fn()}
        onToggleSystemProxy={vi.fn().mockResolvedValue(undefined)}
        onOpenThemeForge={vi.fn()}
        onToggleLanguage={vi.fn()}
        onOpenWizard={vi.fn()}
        onOpenGlossary={vi.fn()}
        onOpenLauncher={vi.fn()}
        onImportProfile={vi.fn()}
        onExportProfile={vi.fn()}
        onAllocateDns={vi.fn()}
        onFlushDns={vi.fn()}
        onClearLogs={vi.fn()}
        pacEnabled={false}
        pacUrl="http://127.0.0.1:10811/proxy.pac"
        autostartEnabled={false}
        profiles={[
          { profileId: 'default', name: 'Default', proxyCount: 1, ruleCount: 3, active: true },
          { profileId: 'edge-work', name: 'Edge Work', proxyCount: 2, ruleCount: 5, active: false }
        ]}
        onTogglePac={onTogglePac}
        onCopyPacUrl={vi.fn()}
        onToggleAutostart={onToggleAutostart}
        onSaveNamedProfile={vi.fn().mockResolvedValue(undefined)}
        onSwitchNamedProfile={onSwitchNamedProfile}
        onDeleteNamedProfile={vi.fn().mockResolvedValue(undefined)}
      />
    );

    expect(screen.getByText('http://127.0.0.1:10811/proxy.pac')).toBeInTheDocument();
    fireEvent.click(screen.getByText(i18n.t('settings.system.pac_disabled')));
    expect(onTogglePac).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText(i18n.t('settings.system.autostart_disabled')));
    expect(onToggleAutostart).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText(i18n.t('settings.profiles.switch_button')));
    expect(onSwitchNamedProfile).toHaveBeenCalledWith('edge-work');
  });
});
