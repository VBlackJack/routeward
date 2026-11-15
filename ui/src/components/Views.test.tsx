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
import { ConnectionsView } from './ConnectionsView';
import { DnsView } from './DnsView';
import { ProxiesView } from './ProxiesView';
import { RulesView } from './RulesView';
import {
  FakeIpEntry,
  ProxyChain,
  ProxyNode,
  RoutingRule,
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
});
