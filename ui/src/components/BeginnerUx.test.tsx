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
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import {
  computeProtectionHealth,
  ProtectionHealth
} from '../services/protectionHealth';
import {
  ProxyHealthReport,
  ProxyNode,
  RoutingRule,
  SecurityPolicyConfig,
  SystemDiagnostics,
  TelemetrySnapshot,
  TrackedConnection
} from '../types/routeward';
import { ActivityWhy } from './ActivityWhy';
import { DashboardView } from './DashboardView';
import { GlossaryModal } from './GlossaryModal';
import { HelpTooltip } from './HelpTooltip';
import { QuickSetupWizardModal } from './QuickSetupWizardModal';
import { ProxiesView } from './ProxiesView';
import { TroubleshootModal } from './TroubleshootModal';

function makeProxy(id: string, host: string): ProxyNode {
  return {
    id,
    name: `Proxy ${host}`,
    protocol: 'socks5',
    host,
    port: 1080,
    auth: null,
    udpEnabled: true,
    tls: false,
    sni: null,
    enabled: true,
    lastLatencyMs: null,
    exitIp: null
  };
}

const telemetry: TelemetrySnapshot = {
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
};

const policy: SecurityPolicyConfig = {
  killSwitchEnabled: true,
  blockUdpOnTcpOnlyProxy: true,
  strictDnsNoLocalFallback: true
};

function makeDiagnostics(overrides: Partial<SystemDiagnostics>): SystemDiagnostics {
  return {
    daemonConnected: true,
    running: true,
    osName: 'WINDOWS',
    interceptionMode: 'hybrid',
    elevatedPrivileges: true,
    relayTcpEndpoint: '127.0.0.1:10808',
    relayHttpEndpoint: '127.0.0.1:10809',
    dnsEndpoint: '127.0.0.1:5353',
    fakeIpCidr: '198.18.0.0/15',
    activeLocale: 'en',
    pausedUntilEpochMs: null,
    autoStartErrorKey: null,
    ...overrides
  };
}

function renderSimpleHome(
  diagnostics: SystemDiagnostics,
  proxies: ProxyNode[],
  health?: ProtectionHealth,
  extra: Partial<React.ComponentProps<typeof DashboardView>> = {}
) {
  return render(
    <DashboardView
      telemetry={telemetry}
      diagnostics={diagnostics}
      dnsCount={0}
      securityPolicy={policy}
      experienceMode="simple"
      proxies={proxies}
      health={health}
      onToggleEngine={vi.fn()}
      onUpdateSecurityPolicy={vi.fn()}
      onOpenWizard={vi.fn()}
      onNavigateRules={vi.fn()}
      onSwitchToExpert={vi.fn()}
      {...extra}
    />
  );
}

describe('Beginner UX: shared protection health on the home hero', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('never says the IP address is hidden when protection runs without a proxy', async () => {
    await i18n.changeLanguage('en');
    renderSimpleHome(makeDiagnostics({}), []);
    expect(
      screen.getByRole('heading', {
        name: i18n.t('dashboard.health.active_no_proxy.title')
      })
    ).toBeInTheDocument();
    expect(
      screen.getByText(i18n.t('dashboard.health.active_no_proxy.desc'))
    ).toBeInTheDocument();
    expect(screen.queryByText(/protected: your proxy answers/i)).not.toBeInTheDocument();
  });

  it('shows the pause end time and resumes with the start action', async () => {
    await i18n.changeLanguage('en');
    const onToggleEngine = vi.fn();
    const until = new Date(2030, 0, 1, 9, 30, 0).getTime();
    const diagnostics = makeDiagnostics({ running: false, pausedUntilEpochMs: until });
    renderSimpleHome(diagnostics, [], undefined, { onToggleEngine });

    expect(
      screen.getByRole('heading', {
        name: i18n.t('dashboard.health.paused.title', { time: '09:30' })
      })
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('dashboard.simple.resume_now') })
    );
    expect(onToggleEngine).toHaveBeenCalledTimes(1);
  });

  it('shows the proxy-unreachable state from the shared health model', async () => {
    await i18n.changeLanguage('en');
    const proxy = makeProxy('p1', 'proxy.example.com');
    const diagnostics = makeDiagnostics({});
    const health = computeProtectionHealth({
      diagnostics,
      primaryProxy: proxy,
      proxyReachability: 'unreachable'
    });
    renderSimpleHome(diagnostics, [proxy], health);
    expect(
      screen.getByRole('heading', {
        name: i18n.t('dashboard.health.active_proxy_unreachable.title')
      })
    ).toBeInTheDocument();
  });

  it('shows "not hidden" in the verify panel while protection is paused', async () => {
    await i18n.changeLanguage('en');
    const proxy = makeProxy('p1', 'proxy.example.com');
    const diagnostics = makeDiagnostics({
      running: false,
      pausedUntilEpochMs: Date.now() + 600_000
    });
    renderSimpleHome(diagnostics, [proxy], undefined, {
      onTestPrimaryProxy: vi.fn().mockResolvedValue({
        proxyId: 'p1',
        reachable: true,
        latencyMs: 20,
        udpSupported: true,
        exitIp: '203.0.113.9',
        errorDetail: null
      } satisfies ProxyHealthReport)
    });
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('dashboard.simple.verify_protection_cta') })
    );
    await waitFor(() =>
      expect(
        screen.getByText(i18n.t('dashboard.simple.verify_ip_paused'))
      ).toBeInTheDocument()
    );
    expect(
      screen.queryByText(new RegExp(i18n.t('dashboard.simple.verify_ip_masked')))
    ).not.toBeInTheDocument();
  });

  it('forgets the exit IP of the previous proxy when the primary proxy changes', async () => {
    await i18n.changeLanguage('en');
    const first = makeProxy('p1', 'one.example.com');
    const second = makeProxy('p2', 'two.example.com');
    const report: ProxyHealthReport = {
      proxyId: 'p1',
      reachable: true,
      latencyMs: 20,
      udpSupported: true,
      exitIp: '203.0.113.9',
      errorDetail: null
    };
    const props = {
      telemetry,
      dnsCount: 0,
      securityPolicy: policy,
      experienceMode: 'simple' as const,
      onToggleEngine: vi.fn(),
      onUpdateSecurityPolicy: vi.fn(),
      onOpenWizard: vi.fn(),
      onNavigateRules: vi.fn(),
      onSwitchToExpert: vi.fn(),
      onTestPrimaryProxy: vi.fn().mockResolvedValue(report)
    };
    const diagnostics = makeDiagnostics({});
    const { rerender } = render(
      <DashboardView {...props} diagnostics={diagnostics} proxies={[first]} />
    );
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('dashboard.simple.verify_protection_cta') })
    );
    await waitFor(() =>
      expect(screen.getAllByText(/203\.0\.113\.9/).length).toBeGreaterThan(0)
    );
    rerender(<DashboardView {...props} diagnostics={diagnostics} proxies={[second]} />);
    await waitFor(() =>
      expect(screen.queryAllByText(/203\.0\.113\.9/)).toHaveLength(0)
    );
  });

  it('derives the "applied" badge from the profile, not from a click', async () => {
    await i18n.changeLanguage('en');
    const rules: RoutingRule[] = [];
    renderSimpleHome(makeDiagnostics({}), [], undefined, {
      rules,
      securityPolicy: {
        killSwitchEnabled: true,
        blockUdpOnTcpOnlyProxy: true,
        strictDnsNoLocalFallback: true,
        blockQuicUdp443: true,
        blockEncryptedDnsBypass: true
      }
    });
    expect(
      screen.queryByText(i18n.t('dashboard.simple.use_case_applied_badge'))
    ).not.toBeInTheDocument();
  });
});

describe('Beginner UX: setup assistant', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  function goToStep2() {
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
  }

  it('keeps an unreadable link, explains it with an example, and never reports success', async () => {
    const onComplete = vi.fn();
    const onAddRule = vi.fn().mockResolvedValue(undefined);
    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn().mockResolvedValue([])}
        onAddRule={onAddRule}
        onSelectMode={vi.fn()}
        onComplete={onComplete}
        onClose={vi.fn()}
      />
    );
    await goToStep2();
    const textarea = screen.getByPlaceholderText(i18n.t('wizard.modal.step2_uri_placeholder'));
    fireEvent.change(textarea, { target: { value: 'not a proxy link at all' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));

    expect(
      await screen.findByText(i18n.t('wizard.modal.step2_link_unreadable'))
    ).toBeInTheDocument();
    expect(i18n.t('wizard.modal.step2_link_unreadable')).toContain('socks5://');
    expect(
      screen.getByPlaceholderText(i18n.t('wizard.modal.step2_uri_placeholder'))
    ).toHaveValue('not a proxy link at all');
    expect(onComplete).not.toHaveBeenCalled();
    expect(onAddRule).not.toHaveBeenCalled();
  });

  it('replaces a failed manual draft on retry and uses the tested proxy as the primary', async () => {
    let store: ProxyNode[] = [];
    const onAddProxy = vi.fn().mockImplementation(async (node: ProxyNode) => {
      store = [...store, node];
      return store;
    });
    const onRemoveProxy = vi.fn().mockImplementation(async (id: string) => {
      store = store.filter((p) => p.id !== id);
    });
    const onTestProxy = vi
      .fn()
      .mockResolvedValueOnce({ proxyId: 'x', reachable: false, latencyMs: null, udpSupported: false })
      .mockResolvedValueOnce({ proxyId: 'y', reachable: true, latencyMs: 12, udpSupported: true });
    const onAddRule = vi.fn().mockResolvedValue(undefined);
    const onComplete = vi.fn();

    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onAddProxy={onAddProxy}
        onRemoveProxy={onRemoveProxy}
        onTestProxy={onTestProxy}
        onAddRule={onAddRule}
        onSelectMode={vi.fn()}
        onComplete={onComplete}
        onClose={vi.fn()}
      />
    );
    await goToStep2();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.step2_tab_manual') }));

    const hostField = () => screen.getByLabelText(i18n.t('wizard.modal.step2_manual_host'));
    fireEvent.change(hostField(), { target: { value: 'bad.example.com' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.step2_test_button') }));
    await waitFor(() => expect(onTestProxy).toHaveBeenCalledTimes(1));
    const failedId = (onAddProxy.mock.calls[0][0] as ProxyNode).id;
    await screen.findByText(i18n.t('wizard.modal.step2_test_failed'));

    fireEvent.change(hostField(), { target: { value: 'good.example.com' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.step2_test_button') }));
    await waitFor(() => expect(onTestProxy).toHaveBeenCalledTimes(2));

    expect(onRemoveProxy).toHaveBeenCalledWith(failedId);
    const goodId = (onAddProxy.mock.calls[1][0] as ProxyNode).id;
    expect(onTestProxy.mock.calls[1][0]).toBe(goodId);
    expect(store.map((p) => p.id)).toEqual([goodId]);

    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));
    await waitFor(() => expect(onComplete).toHaveBeenCalledWith(true));
    const browserRule = onAddRule.mock.calls
      .map((c) => c[0] as RoutingRule)
      .find((r) => r.id === 'rule-wiz-preset-privacy-browsers');
    expect(browserRule?.action).toEqual({ type: 'proxy', targetId: goodId });
  });

  it('ends with "saved, but protection could not start" and a retry, without a success message', async () => {
    const onEnableProtection = vi
      .fn()
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);
    const onComplete = vi.fn();
    const onConfigSaved = vi.fn();
    const onVerifyProtection = vi.fn();
    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onEnableProtection={onEnableProtection}
        onAddRule={vi.fn().mockResolvedValue(undefined)}
        onSelectMode={vi.fn()}
        onComplete={onComplete}
        onConfigSaved={onConfigSaved}
        onVerifyProtection={onVerifyProtection}
        onClose={vi.fn()}
      />
    );
    await goToStep2();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.finish') }));

    expect(
      await screen.findByText(i18n.t('wizard.done.protection_failed_title'))
    ).toBeInTheDocument();
    expect(onConfigSaved).toHaveBeenCalledTimes(1);
    expect(onComplete).not.toHaveBeenCalled();
    expect(screen.queryByText(i18n.t('wizard.done.title'))).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.done.retry') }));
    await waitFor(() => expect(onComplete).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.done.verify') }));
    expect(onVerifyProtection).toHaveBeenCalledTimes(1);
  });

  it('says exactly what will happen: no tracker blocking promise without a blocking rule', async () => {
    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onAddRule={vi.fn()}
        onSelectMode={vi.fn()}
        onComplete={vi.fn()}
        onClose={vi.fn()}
      />
    );
    fireEvent.click(
      screen.getByRole('radio', {
        name: new RegExp(i18n.t('wizard.modal.step1_work_title'))
      })
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    expect(screen.getByText(i18n.t('wizard.summary.no_proxy_ip_visible'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('wizard.summary.block_telemetry'))).not.toBeInTheDocument();
    expect(screen.getByText(i18n.t('wizard.summary.local_network_direct'))).toBeInTheDocument();
  });

  it('exposes the goal cards as a radio group', async () => {
    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onAddRule={vi.fn()}
        onSelectMode={vi.fn()}
        onComplete={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getAllByRole('radio')).toHaveLength(3);
    expect(screen.getAllByRole('radio').filter((r) => r.getAttribute('aria-checked') === 'true')).toHaveLength(1);
  });

  it('reports a failed proxy search as a failure, not as "none found"', async () => {
    await i18n.changeLanguage('en');
    render(
      <QuickSetupWizardModal
        proxies={[]}
        chains={[]}
        currentMode="simple"
        onImportUris={vi.fn()}
        onDetectExistingProxies={vi.fn().mockRejectedValue(new Error('network down'))}
        onAddRule={vi.fn()}
        onSelectMode={vi.fn()}
        onComplete={vi.fn()}
        onClose={vi.fn()}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('wizard.modal.next') }));
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('wizard.modal.step2_detect_button') })
    );
    expect(
      await screen.findByText(i18n.t('wizard.modal.step2_detect_failed'))
    ).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('proxies.simple.detect_empty'))).not.toBeInTheDocument();
  });
});

describe('Beginner UX: proxy detection on the proxy tab', () => {
  afterEach(() => {
    cleanup();
  });

  it('says the detection failed instead of "none found"', async () => {
    await i18n.changeLanguage('en');
    render(
      <ProxiesView
        proxies={[]}
        chains={[]}
        experienceMode="simple"
        onDetectExistingProxies={vi.fn().mockRejectedValue(new Error('network down'))}
        onTestProxy={vi.fn()}
        onTestAllProxies={vi.fn()}
        onAddProxy={vi.fn()}
        onImportUris={vi.fn()}
        onCopyUri={vi.fn()}
        onRemoveProxy={vi.fn()}
        onAddChain={vi.fn()}
        onRemoveChain={vi.fn()}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('proxies.simple.detect_button') }));
    expect(await screen.findByText(i18n.t('proxies.simple.detect_failed'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('proxies.simple.detect_empty'))).not.toBeInTheDocument();
  });
});

describe('Beginner UX: troubleshooter', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  function failure(id: string, detail: string): TrackedConnection {
    return {
      id,
      pid: 10,
      processName: `app-${id}.exe`,
      processPath: `C:\\Apps\\app-${id}.exe`,
      targetHost: `site-${id}.example.com`,
      resolvedDomain: null,
      targetPort: 443,
      protocol: 'tcp',
      matchedRule: 'Proxy rule',
      routeLabel: 'BLOCKED',
      latencyMs: 0,
      rxBytes: 0,
      txBytes: 0,
      status: 'blocked',
      startedAt: '2026-11-22T10:00:00Z',
      errorDetail: detail
    };
  }

  it('leads with "your proxy is not responding" when most failures are proxy outages', async () => {
    await i18n.changeLanguage('en');
    const onTestProxy = vi.fn();
    const onPauseProtection = vi.fn();
    const onChangeProxy = vi.fn();
    render(
      <TroubleshootModal
        connections={[
          failure('a', 'upstream proxy unreachable'),
          failure('b', 'connection timed out'),
          failure('c', 'blocked by rule')
        ]}
        onTestProxy={onTestProxy}
        onPauseProtection={onPauseProtection}
        onChangeProxy={onChangeProxy}
        onAllowAppDirect={vi.fn()}
        onAllowSiteDirect={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(i18n.t('troubleshoot.proxy_down.title'))).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('troubleshoot.proxy_down.test') }));
    fireEvent.click(
      screen.getByRole('button', { name: i18n.t('troubleshoot.proxy_down.pause', { minutes: 15 }) })
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('troubleshoot.proxy_down.change') }));
    expect(onTestProxy).toHaveBeenCalledTimes(1);
    expect(onPauseProtection).toHaveBeenCalledWith(15);
    expect(onChangeProxy).toHaveBeenCalledTimes(1);
    expect(screen.getByText(i18n.t('troubleshoot.modal.allow_warning'))).toBeInTheDocument();
  });

  it('offers the pause only while protection is active', async () => {
    await i18n.changeLanguage('en');
    const stopped = computeProtectionHealth({
      diagnostics: makeDiagnostics({ running: false }),
      primaryProxy: null,
      proxyReachability: 'unknown'
    });
    const pauseLabel = i18n.t('troubleshoot.proxy_down.pause', { minutes: 15 });
    const failures = [failure('a', 'upstream proxy unreachable'), failure('b', 'connection timed out')];
    const { rerender } = render(
      <TroubleshootModal
        connections={failures}
        health={stopped}
        onPauseProtection={vi.fn()}
        onAllowAppDirect={vi.fn()}
        onAllowSiteDirect={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.queryByRole('button', { name: pauseLabel })).not.toBeInTheDocument();

    const active = computeProtectionHealth({
      diagnostics: makeDiagnostics({ running: true }),
      primaryProxy: null,
      proxyReachability: 'unknown'
    });
    rerender(
      <TroubleshootModal
        connections={failures}
        health={active}
        onPauseProtection={vi.fn()}
        onAllowAppDirect={vi.fn()}
        onAllowSiteDirect={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: pauseLabel })).toBeInTheDocument();
  });

  it('does not lead with the proxy outage when failures come from rules', async () => {
    await i18n.changeLanguage('en');
    render(
      <TroubleshootModal
        connections={[failure('a', 'blocked by rule'), failure('b', 'blocked by rule')]}
        onTestProxy={vi.fn()}
        onAllowAppDirect={vi.fn()}
        onAllowSiteDirect={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.queryByText(i18n.t('troubleshoot.proxy_down.title'))).not.toBeInTheDocument();
  });

  it('explains an empty list when protection is paused or the service is stopped', async () => {
    await i18n.changeLanguage('en');
    const diagnostics = makeDiagnostics({ running: false, pausedUntilEpochMs: Date.now() + 60_000 });
    const paused = computeProtectionHealth({
      diagnostics,
      primaryProxy: null,
      proxyReachability: 'unknown'
    });
    const { rerender } = render(
      <TroubleshootModal
        connections={[]}
        health={paused}
        onAllowAppDirect={vi.fn()}
        onAllowSiteDirect={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(/nothing is blocked while it is paused/i)).toBeInTheDocument();

    const stopped = computeProtectionHealth({
      diagnostics: makeDiagnostics({ daemonConnected: false, running: false }),
      primaryProxy: null,
      proxyReachability: 'unknown'
    });
    rerender(
      <TroubleshootModal
        connections={[]}
        health={stopped}
        onAllowAppDirect={vi.fn()}
        onAllowSiteDirect={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(i18n.t('troubleshoot.modal.empty_stopped'))).toBeInTheDocument();
  });
});

describe('Beginner UX: help and activity', () => {
  afterEach(() => {
    cleanup();
  });

  it('keeps the tooltip open when it is hovered and then clicked', () => {
    render(<HelpTooltip text="Plain explanation" />);
    const button = screen.getByRole('button');
    fireEvent.mouseEnter(button.parentElement as HTMLElement);
    expect(screen.getByRole('tooltip')).toBeInTheDocument();
    fireEvent.click(button);
    expect(screen.getByRole('tooltip')).toBeInTheDocument();
    fireEvent.click(button);
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });

  it('hides the technical column of the glossary in Simple mode', async () => {
    await i18n.changeLanguage('en');
    const { rerender } = render(<GlossaryModal experienceMode="simple" onClose={vi.fn()} />);
    expect(screen.getByText(i18n.t('glossary.items.service.term'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('glossary.items.port.term'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('glossary.items.ip_address.term'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('glossary.items.protocol.term'))).toBeInTheDocument();
    expect(screen.queryByText(i18n.t('glossary.items.proxy.expert'))).not.toBeInTheDocument();
    rerender(<GlossaryModal experienceMode="expert" onClose={vi.fn()} />);
    expect(screen.getByText(i18n.t('glossary.items.proxy.expert'))).toBeInTheDocument();
  });

  it('answers "why?" for a blocked app with the rule and the translated reason', async () => {
    await i18n.changeLanguage('en');
    const conn: TrackedConnection = {
      id: 'c1',
      pid: 1,
      processName: 'firefox.exe',
      processPath: 'C:\\Firefox\\firefox.exe',
      targetHost: 'example.com',
      resolvedDomain: null,
      targetPort: 443,
      protocol: 'tcp',
      matchedRule: 'Block Firefox',
      routeLabel: 'BLOCKED',
      latencyMs: 0,
      rxBytes: 0,
      txBytes: 0,
      status: 'blocked',
      startedAt: '2026-11-22T10:00:00Z',
      errorDetail: 'kill-switch: upstream unreachable'
    };
    render(<ActivityWhy connection={conn} />);
    fireEvent.click(screen.getByRole('button', { name: i18n.t('troubleshoot.why.button') }));
    expect(screen.getByText(i18n.t('troubleshoot.reasons.killswitch'))).toBeInTheDocument();
    expect(
      screen.getByText(i18n.t('troubleshoot.why.rule', { name: 'Block Firefox' }))
    ).toBeInTheDocument();
  });

  it('shows nothing for a connection that works', () => {
    const conn = {
      id: 'c2',
      pid: 1,
      processName: 'firefox.exe',
      processPath: '',
      targetHost: 'example.com',
      resolvedDomain: null,
      targetPort: 443,
      protocol: 'tcp',
      matchedRule: 'Direct',
      routeLabel: 'DIRECT',
      latencyMs: 0,
      rxBytes: 0,
      txBytes: 0,
      status: 'active',
      startedAt: '2026-11-22T10:00:00Z'
    } as TrackedConnection;
    const { container } = render(<ActivityWhy connection={conn} />);
    expect(container).toBeEmptyDOMElement();
  });
});
