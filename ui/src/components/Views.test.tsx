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
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { UI_CONFIG } from '../config/constants';
import { formatProxyUri, parseSingleProxyUri } from '../services/uri';
import { ConnectionsView } from './ConnectionsView';
import { DashboardView } from './DashboardView';
import { DnsView } from './DnsView';
import { ProxiesView } from './ProxiesView';
import { QuickSetupWizardModal } from './QuickSetupWizardModal';
import { RulesView } from './RulesView';
import { SettingsView } from './SettingsView';
import { TroubleshootModal } from './TroubleshootModal';
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
    expect(onRemoveRule).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole('button', {
        name: `${i18n.t('app.confirm_delete.confirm')}: ${i18n.t('rules.table.controls.delete')}: LAN Direct`
      })
    );
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

    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true
    });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.card.action.copy_uri') })
    );
    // The copy confirmation fires only after the clipboard write resolved.
    await waitFor(() =>
      expect(onCopyUri).toHaveBeenCalledWith(
        'socks5://[2001:db8::1]:1080#Frankfurt%20SOCKS5'
      )
    );
    expect(writeText).toHaveBeenCalledWith(
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
    expect(onRemoveChain).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole('button', {
        name: `${i18n.t('app.confirm_delete.confirm')}: ${i18n.t('proxies.section.chains.delete')}`
      })
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
    const dialog = within(screen.getByRole('dialog'));
    fireEvent.click(
      dialog.getByRole('button', { name: i18n.t('connections.simple.route_direct') })
    );
    fireEvent.click(dialog.getByRole('button', { name: i18n.t('rules.modal.add.submit') }));

    expect(onAddRule).toHaveBeenCalledTimes(1);
    expect(onAddRule.mock.calls[0][0].processPatterns).toEqual(['spotify.exe']);
    expect(onAddRule.mock.calls[0][0].action).toEqual({ type: 'direct' });
    expect(onAddRule.mock.calls[0][0].id).toBe('rule-app-spotify-exe');
    expect(onAddRule.mock.calls[0][0].priority).toBe(UI_CONFIG.SIMPLE_APP_RULE_PRIORITY);
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
      screen.getByText(i18n.t('connections.simple.count_connections', { count: 2 }))
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

  it('RulesView simple mode supports combined msedge.exe + meshcore.net proxy rules and guards missing proxy', () => {
    const onMissingProxy = vi.fn();
    const onAddRule = vi.fn();
    const { rerender } = render(
      <RulesView
        rules={[]}
        proxies={[]}
        chains={[]}
        experienceMode="simple"
        onEvaluateRule={vi.fn()}
        onAddRule={onAddRule}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
        onMissingProxy={onMissingProxy}
      />
    );

    const proxyButtons = screen.getAllByRole('button', {
      name: i18n.t('rules.visual_apps.action_proxy')
    });
    fireEvent.click(proxyButtons[0]);
    expect(onMissingProxy).toHaveBeenCalledTimes(1);
    expect(onAddRule).not.toHaveBeenCalled();

    const extProxy: ProxyNode = {
      id: 'p-ext',
      name: 'External SSH Relay',
      protocol: 'socks5',
      host: 'proxy.example.com',
      port: 1080,
      auth: null,
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    };

    rerender(
      <RulesView
        rules={[]}
        proxies={[extProxy]}
        chains={[]}
        experienceMode="simple"
        onEvaluateRule={vi.fn()}
        onAddRule={onAddRule}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
        onMissingProxy={onMissingProxy}
      />
    );

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.simple.add_button') })
    );
    fireEvent.click(
      screen.getByRole('button', { name: `+ ${i18n.t('rules.simple.quick_edge_chip')}` })
    );
    const domainInput = screen.getByPlaceholderText(
      i18n.t('rules.simple.optional_site_placeholder')
    );
    fireEvent.change(domainInput, {
      target: { value: 'meshcore.net, *.meshcore.net' }
    });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('rules.modal.add.submit') })
    );

    expect(onAddRule).toHaveBeenCalledTimes(1);
    const createdRule = onAddRule.mock.calls[0][0] as RoutingRule;
    expect(createdRule.processPatterns).toEqual(['msedge.exe']);
    expect(createdRule.domainPatterns).toEqual(['*.meshcore.net']);
    expect(createdRule.action).toEqual({ type: 'proxy', targetId: 'p-ext' });

    // Reopening this combined process+domain rule stays in simple mode with both values prefilled
    rerender(
      <RulesView
        rules={[createdRule]}
        proxies={[extProxy]}
        chains={[]}
        experienceMode="simple"
        onEvaluateRule={vi.fn()}
        onAddRule={onAddRule}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
        onMissingProxy={onMissingProxy}
      />
    );

    fireEvent.click(
      screen.getByRole('button', {
        name: `${i18n.t('rules.table.controls.edit')}: ${createdRule.name}`
      })
    );
    expect(
      screen.getByPlaceholderText(i18n.t('rules.simple.target_app_placeholder'))
    ).toHaveValue('msedge.exe');
    expect(
      screen.getByPlaceholderText(i18n.t('rules.simple.optional_site_placeholder'))
    ).toHaveValue('*.meshcore.net');
  });

  it('DashboardView and QuickSetupWizardModal default to Direct Filter Mode without dummy 127.0.0.1:1080', async () => {
    const telemetry: TelemetrySnapshot = {
      activeConnections: 0,
      downloadBytesPerSec: 0,
      uploadBytesPerSec: 0,
      totalRxBytes: 0,
      totalTxBytes: 0,
      proxiedCount: 0,
      directCount: 2,
      blockedCount: 1,
      bandwidthHistory: [],
      topTalkers: []
    };
    const diagnostics: SystemDiagnostics = {
      daemonConnected: true,
      running: true,
      osName: 'WINDOWS',
      interceptionMode: 'hybrid',
      elevatedPrivileges: true,
      relayTcpEndpoint: '127.0.0.1:10808',
      relayHttpEndpoint: '127.0.0.1:10809',
      dnsEndpoint: '127.0.0.1:5353',
      fakeIpCidr: '198.18.0.0/15',
      activeLocale: 'en'
    };
    const securityPolicy: SecurityPolicyConfig = {
      killSwitchEnabled: true,
      blockUdpOnTcpOnlyProxy: true,
      strictDnsNoLocalFallback: true
    };

    render(
      <DashboardView
        telemetry={telemetry}
        diagnostics={diagnostics}
        dnsCount={0}
        securityPolicy={securityPolicy}
        experienceMode="simple"
        proxies={[]}
        onApplyUseCase={vi.fn()}
        onUpdateSecurityPolicy={vi.fn()}
        onOpenWizard={vi.fn()}
        onNavigateRules={vi.fn()}
        onSwitchToExpert={vi.fn()}
      />
    );

    expect(
      screen.getByText(i18n.t('dashboard.simple.direct_filter_mode_title'))
    ).toBeInTheDocument();

    cleanup();

    const onAddRule = vi.fn().mockResolvedValue(undefined);
    const onComplete = vi.fn();
    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onAddRule={onAddRule}
        onSelectMode={vi.fn()}
        onComplete={onComplete}
        onClose={vi.fn()}
      />
    );

    // Step 1 -> Step 2
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    expect(
      screen.getByText(i18n.t('wizard.modal.step2_no_proxy_title'))
    ).toBeInTheDocument();
    expect(screen.queryByText('SOCKS5 127.0.0.1:1080')).not.toBeInTheDocument();

    // Step 2 -> Step 3 -> Finish without pasting any proxy URI
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));

    await waitFor(() => expect(onComplete).toHaveBeenCalledWith(false));
    const appliedIds = onAddRule.mock.calls.map((c) => (c[0] as RoutingRule).id);
    expect(appliedIds).toEqual([
      'rule-wiz-preset-block-os-telemetry',
      'rule-wiz-preset-rfc1918-direct'
    ]);

    cleanup();

    const importedProxy: ProxyNode = {
      id: 'imported-ext-1',
      name: 'ExternalProxy',
      protocol: 'socks5',
      host: 'proxy.example.com',
      port: 1080,
      auth: null,
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    };
    const onAddWithProxy = vi.fn().mockResolvedValue(undefined);
    const onCompleteWithProxy = vi.fn();
    const onImportUris = vi.fn().mockResolvedValue([importedProxy]);

    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={onImportUris}
        onAddRule={onAddWithProxy}
        onSelectMode={vi.fn()}
        onComplete={onCompleteWithProxy}
        onClose={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.change(
      screen.getByPlaceholderText(i18n.t('wizard.modal.step2_uri_placeholder')),
      { target: { value: 'socks5://user:pass@proxy.example.com:1080#ExternalProxy' } }
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));

    await waitFor(() => expect(onCompleteWithProxy).toHaveBeenCalledWith(true));
    const privacyBrowserRule = onAddWithProxy.mock.calls
      .map((c) => c[0] as RoutingRule)
      .find((r) => r.id === 'rule-wiz-preset-privacy-browsers');
    expect(privacyBrowserRule?.action).toEqual({
      type: 'proxy',
      targetId: 'imported-ext-1'
    });
  });

  it('supports beginner proxy link paste, port validation, in-use delete warning, and SettingsView simple accordion', async () => {
    const onAddProxy = vi.fn();
    const onRemoveProxy = vi.fn();
    const existingProxy: ProxyNode = {
      id: 'p-used',
      name: 'Work Proxy',
      protocol: 'socks5',
      host: 'proxy.example.com',
      port: 1080,
      auth: null,
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: 31,
      exitIp: null
    };
    const ruleUsingProxy: RoutingRule = {
      id: 'r-uses-p',
      name: 'Browsers',
      enabled: true,
      priority: 10,
      processPatterns: ['firefox.exe'],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action: { type: 'proxy', targetId: 'p-used' }
    };

    render(
      <ProxiesView
        proxies={[existingProxy]}
        chains={[]}
        rules={[ruleUsingProxy]}
        experienceMode="simple"
        onTestProxy={vi.fn().mockResolvedValue(undefined)}
        onTestAllProxies={vi.fn().mockResolvedValue(undefined)}
        onAddProxy={onAddProxy}
        onImportUris={vi.fn()}
        onCopyUri={vi.fn()}
        onRemoveProxy={onRemoveProxy}
        onAddChain={vi.fn()}
        onRemoveChain={vi.fn()}
      />
    );

    // Simple mode exposes the paste link button and human-friendly status
    expect(
      screen.getByRole('button', { name: i18n.t('proxies.simple.paste_link_button') })
    ).toBeInTheDocument();
    expect(screen.getByText(i18n.t('proxies.simple.status_ok'))).toBeInTheDocument();
    expect(screen.queryByText(/ms\)/)).not.toBeInTheDocument();

    // Deleting a referenced proxy shows an inline warning and requires confirmation
    fireEvent.click(screen.getByRole('button', { name: i18n.t('proxies.card.action.delete') }));
    expect(onRemoveProxy).not.toHaveBeenCalled();
    expect(
      screen.getByText(i18n.t('proxies.delete.warning_disable', { count: 1 }))
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', {
        name: `${i18n.t('app.confirm_delete.confirm')}: ${i18n.t('proxies.card.action.delete')}`
      })
    );
    expect(onRemoveProxy).toHaveBeenCalledWith('p-used');

    // Quick-paste URI in Add Proxy modal auto-fills fields and validates ports
    fireEvent.click(screen.getByRole('button', { name: i18n.t('proxies.simple.add') }));
    const quickPasteInput = screen.getByLabelText(
      i18n.t('proxies.modal.add_proxy.quick_paste_label')
    );
    fireEvent.change(quickPasteInput, {
      target: { value: 'https://alice:pw@edge.example.com:8443#AutoFilled' }
    });
    // Nothing is parsed while typing: the link is read when the field is left.
    expect(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.host_label'))).toHaveValue('');
    fireEvent.blur(quickPasteInput);
    expect(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.name_label'))).toHaveValue(
      'AutoFilled'
    );
    expect(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.host_label'))).toHaveValue(
      'edge.example.com'
    );
    expect(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.port_label'))).toHaveValue(8443);

    fireEvent.change(screen.getByLabelText(i18n.t('proxies.modal.add_proxy.port_label')), {
      target: { value: '70000' }
    });
    fireEvent.submit(
      screen.getByLabelText(i18n.t('proxies.modal.add_proxy.port_label')).closest('form')!
    );
    expect(screen.getByRole('alert')).toHaveTextContent(
      i18n.t('proxies.modal.add_proxy.port_error')
    );
    expect(onAddProxy).not.toHaveBeenCalled();

    cleanup();

    // SettingsView Simple mode collapses advanced system tools until toggled open
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
          dnsEndpoint: '127.0.0.1:10853',
          fakeIpCidr: '198.18.0.0/15',
          activeLocale: 'en'
        }}
        securityPolicy={{
          killSwitchEnabled: true,
          blockUdpOnTcpOnlyProxy: true,
          strictDnsNoLocalFallback: true
        }}
        experienceMode="simple"
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
      />
    );

    expect(screen.queryByText(i18n.t('settings.system.pac_title'))).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('settings.system.advanced_tools_show') })
    );
    expect(screen.getByText(i18n.t('settings.system.pac_title'))).toBeInTheDocument();
  });

  it('QuickSetupWizardModal supports manual proxy input and gaming goal rule creation', async () => {
    const onAddProxy = vi.fn().mockImplementation(async (node: ProxyNode) => [node]);
    const onAddRule = vi.fn().mockResolvedValue(undefined);
    const onComplete = vi.fn();

    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onAddProxy={onAddProxy}
        onAddRule={onAddRule}
        onSelectMode={vi.fn()}
        onComplete={onComplete}
        onClose={vi.fn()}
      />
    );

    // Pick Gaming goal on Step 1
    fireEvent.click(screen.getByText(i18n.t('wizard.modal.step1_gaming_title')));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));

    // Switch to manual host & port on Step 2
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('wizard.modal.step2_tab_manual') })
    );
    fireEvent.change(
      screen.getByLabelText(i18n.t('wizard.modal.step2_manual_host')),
      { target: { value: 'proxy.game.example' } }
    );
    fireEvent.change(
      screen.getByLabelText(i18n.t('wizard.modal.step2_manual_port')),
      { target: { value: '1080' } }
    );

    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    expect(
      screen.getByText(i18n.t('wizard.modal.step3_summary_with_proxy'))
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));

    await waitFor(() => expect(onComplete).toHaveBeenCalledWith(true));
    expect(onAddProxy).toHaveBeenCalledTimes(1);
    const createdRuleIds = onAddRule.mock.calls.map((c) => (c[0] as RoutingRule).id);
    expect(createdRuleIds).toContain('rule-visual-app-gaming');
    expect(createdRuleIds).toContain('rule-wiz-preset-privacy-browsers');
    expect(createdRuleIds).toContain('rule-wiz-preset-rfc1918-direct');
  });

  it('TroubleshootModal unblocks failed apps in 1 click and RulesView toggles 1-click protection packs', () => {
    const onAllowAppDirect = vi.fn();
    const onAllowSiteDirect = vi.fn();
    const failedConn: TrackedConnection = {
      id: 'c-fail-1',
      pid: 777,
      processName: 'bank-app.exe',
      processPath: 'C:\\Apps\\bank-app.exe',
      targetHost: '198.51.100.2',
      resolvedDomain: 'secure.mybank.fr',
      targetPort: 443,
      protocol: 'tcp',
      matchedRule: 'KillSwitch',
      routeLabel: 'BLOCKED',
      latencyMs: 0,
      rxBytes: 0,
      txBytes: 0,
      status: 'blocked',
      startedAt: '2026-11-21T10:00:00Z',
      errorDetail: 'Kill-switch blocked connection: proxy unreachable'
    };

    render(
      <TroubleshootModal
        connections={[failedConn]}
        onAllowAppDirect={onAllowAppDirect}
        onAllowSiteDirect={onAllowSiteDirect}
        onClose={vi.fn()}
      />
    );

    expect(screen.getByText('bank-app.exe')).toBeInTheDocument();
    expect(screen.getByText('secure.mybank.fr')).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('troubleshoot.modal.allow_app_direct') })
    );
    expect(onAllowAppDirect).toHaveBeenCalledWith(failedConn);

    cleanup();

    const onAddRule = vi.fn();
    render(
      <RulesView
        rules={[]}
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

    fireEvent.click(screen.getByLabelText(i18n.t('rules.simple.pack_ads_title')));
    expect(onAddRule).toHaveBeenCalledTimes(1);
    expect(onAddRule.mock.calls[0][0].id).toBe('rule-pack-ads-trackers');
    expect(onAddRule.mock.calls[0][0].action).toEqual({ type: 'block' });
  });

  it('keeps unconfigured visual app cards neutral, wires simple failover on rules, and supports clickable dashboard checklist', async () => {
    const onAddRule = vi.fn();
    const failoverChain: ProxyChain = {
      id: 'chain-simple-failover',
      name: 'Backup',
      strategy: 'failover',
      proxyIds: ['p1', 'p2'],
      enabled: true
    };
    const p1: ProxyNode = {
      id: 'p1',
      name: 'Primary',
      protocol: 'socks5',
      host: 'p1.example.com',
      port: 1080,
      auth: null,
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: 25,
      exitIp: null
    };
    const p2: ProxyNode = { ...p1, id: 'p2', name: 'Backup' };

    render(
      <RulesView
        rules={[]}
        proxies={[p1, p2]}
        chains={[failoverChain]}
        experienceMode="simple"
        onEvaluateRule={vi.fn()}
        onAddRule={onAddRule}
        onToggleRule={vi.fn()}
        onReorderRule={vi.fn()}
        onRemoveRule={vi.fn()}
      />
    );

    // No visual app card should appear pressed before any rule exists
    const blockButtons = screen.getAllByRole('button', {
      name: i18n.t('rules.visual_apps.action_block')
    });
    for (const btn of blockButtons) {
      expect(btn).toHaveAttribute('aria-pressed', 'false');
    }

    // Clicking "Via Proxy" when simple failover is active routes via the failover chain
    const proxyButtons = screen.getAllByRole('button', {
      name: i18n.t('rules.visual_apps.action_proxy')
    });
    fireEvent.click(proxyButtons[0]);
    expect(onAddRule).toHaveBeenCalledTimes(1);
    expect(onAddRule.mock.calls[0][0].action).toEqual({
      type: 'chain',
      targetId: 'chain-simple-failover'
    });

    cleanup();

    // DashboardView simple mode: clickable checklist step + closable protection check panel
    const onNavigateRules = vi.fn();
    render(
      <DashboardView
        telemetry={{
          activeConnections: 0,
          downloadBytesPerSec: 0,
          uploadBytesPerSec: 0,
          totalRxBytes: 0,
          totalTxBytes: 0,
          proxiedCount: 0,
          directCount: 0,
          blockedCount: 0,
          bandwidthHistory: [],
          topTalkers: []
        }}
        diagnostics={{
          daemonConnected: true,
          running: false,
          osName: 'WINDOWS',
          interceptionMode: 'hybrid',
          elevatedPrivileges: true,
          relayTcpEndpoint: '127.0.0.1:10808',
          relayHttpEndpoint: '127.0.0.1:10809',
          dnsEndpoint: '127.0.0.1:5353',
          fakeIpCidr: '198.18.0.0/15',
          activeLocale: 'fr'
        }}
        dnsCount={0}
        securityPolicy={{
          killSwitchEnabled: true,
          blockUdpOnTcpOnlyProxy: true,
          strictDnsNoLocalFallback: true
        }}
        experienceMode="simple"
        proxies={[]}
        rules={[]}
        onUpdateSecurityPolicy={vi.fn()}
        onOpenWizard={vi.fn()}
        onNavigateRules={onNavigateRules}
        onSwitchToExpert={vi.fn()}
      />
    );

    fireEvent.click(
      screen.getByRole('button', {
        name: `3. ${i18n.t('dashboard.simple.checklist_step_rules')}`
      })
    );
    expect(onNavigateRules).toHaveBeenCalledTimes(1);

    fireEvent.click(
      screen.getByRole('button', {
        name: i18n.t('dashboard.simple.verify_protection_cta')
      })
    );
    expect(
      await screen.findByText(i18n.t('dashboard.simple.verify_paused_notice'))
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', {
        name: i18n.t('dashboard.simple.verify_close')
      })
    );
    expect(
      screen.queryByText(i18n.t('dashboard.simple.verify_panel_title'))
    ).not.toBeInTheDocument();
  });

  it('wizard enables protection on finish and supports testing a newly entered proxy without duplicating it', async () => {
    const onAddProxy = vi.fn().mockImplementation(async (node: ProxyNode) => [node]);
    const onTestProxy = vi.fn().mockResolvedValue({
      proxyId: 'any',
      reachable: true,
      latencyMs: 33,
      udpSupported: true
    });
    const onEnableProtection = vi.fn().mockResolvedValue(undefined);
    const onAddRule = vi.fn().mockResolvedValue(undefined);
    const onComplete = vi.fn();

    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onAddProxy={onAddProxy}
        onTestProxy={onTestProxy}
        onEnableProtection={onEnableProtection}
        onAddRule={onAddRule}
        onSelectMode={vi.fn()}
        onComplete={onComplete}
        onClose={vi.fn()}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('wizard.modal.step2_tab_manual') })
    );
    fireEvent.change(
      screen.getByLabelText(i18n.t('wizard.modal.step2_manual_host')),
      { target: { value: 'proxy.test.example' } }
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('wizard.modal.step2_test_button') })
    );

    await waitFor(() => expect(onTestProxy).toHaveBeenCalledTimes(1));
    expect(onAddProxy).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));

    await waitFor(() => expect(onComplete).toHaveBeenCalledWith(true));
    expect(onAddProxy).toHaveBeenCalledTimes(1);
    expect(onEnableProtection).toHaveBeenCalledTimes(1);
  });

  it('supports Local LAN 1-click pack, Make Primary proxy button, and Before/After IP check', async () => {
    const onAddRule = vi.fn();
    render(
      <RulesView
        rules={[]}
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

    fireEvent.click(screen.getByLabelText(i18n.t('rules.simple.pack_lan_title')));
    expect(onAddRule).toHaveBeenCalledTimes(1);
    expect(onAddRule.mock.calls[0][0].id).toBe('rule-pack-local-lan');
    expect(onAddRule.mock.calls[0][0].action).toEqual({ type: 'direct' });
    expect(onAddRule.mock.calls[0][0].ipCidrs).toContain('192.168.0.0/16');

    cleanup();

    const p1: ProxyNode = {
      id: 'p1',
      name: 'First',
      protocol: 'socks5',
      host: 'p1.example.com',
      port: 1080,
      auth: null,
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: 20,
      exitIp: '198.51.100.77'
    };
    const p2: ProxyNode = { ...p1, id: 'p2', name: 'Second', exitIp: null };
    const onSetPrimaryProxy = vi.fn();
    const onPasteFromClipboard = vi.fn();

    render(
      <ProxiesView
        proxies={[p1, p2]}
        chains={[]}
        experienceMode="simple"
        onTestProxy={vi.fn().mockResolvedValue(undefined)}
        onTestAllProxies={vi.fn().mockResolvedValue(undefined)}
        onAddProxy={vi.fn()}
        onImportUris={vi.fn()}
        onCopyUri={vi.fn()}
        onRemoveProxy={vi.fn()}
        onAddChain={vi.fn()}
        onRemoveChain={vi.fn()}
        onSetPrimaryProxy={onSetPrimaryProxy}
        onPasteFromClipboard={onPasteFromClipboard}
      />
    );

    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('proxies.simple.set_primary') })
    );
    expect(onSetPrimaryProxy).toHaveBeenCalledWith('p2');

    fireEvent.click(
      screen.getByRole('button', {
        name: i18n.t('proxies.simple.paste_clipboard_button')
      })
    );
    expect(onPasteFromClipboard).toHaveBeenCalledTimes(1);

    cleanup();

    render(
      <DashboardView
        telemetry={{
          activeConnections: 1,
          downloadBytesPerSec: 0,
          uploadBytesPerSec: 0,
          totalRxBytes: 0,
          totalTxBytes: 0,
          proxiedCount: 1,
          directCount: 0,
          blockedCount: 0,
          bandwidthHistory: [],
          topTalkers: []
        }}
        diagnostics={{
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
        }}
        dnsCount={0}
        securityPolicy={{
          killSwitchEnabled: true,
          blockUdpOnTcpOnlyProxy: true,
          strictDnsNoLocalFallback: true
        }}
        experienceMode="simple"
        proxies={[p1]}
        rules={[]}
        onTestPrimaryProxy={vi.fn().mockResolvedValue({
          proxyId: 'p1',
          reachable: true,
          latencyMs: 22,
          udpSupported: true,
          exitIp: '198.51.100.77'
        })}
        onCheckDirectIp={vi.fn().mockResolvedValue('203.0.113.10')}
        onUpdateSecurityPolicy={vi.fn()}
        onOpenWizard={vi.fn()}
        onNavigateRules={vi.fn()}
        onSwitchToExpert={vi.fn()}
      />
    );

    fireEvent.click(
      screen.getByRole('button', {
        name: i18n.t('dashboard.simple.verify_protection_cta')
      })
    );
    await waitFor(() => {
      expect(
        screen.getByText(
          i18n.t('dashboard.simple.verify_before_after', {
            directIp: '203.0.113.10',
            exitIp: '198.51.100.77'
          })
        )
      ).toBeInTheDocument();
    });
  });
});
