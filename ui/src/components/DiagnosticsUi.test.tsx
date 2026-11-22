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
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import i18n from '../i18n';
import { UI_CONFIG } from '../config/constants';
import {
  DiagnosticBundle,
  Finding,
  LogEntry,
  QueryLogsRequest,
  QueryLogsResponse
} from '../types/routeward';
import { AnalyzerPanel } from './AnalyzerPanel';
import { DiagnosticExportModal } from './DiagnosticExportModal';
import { LogsView } from './LogsView';

function log(partial: Partial<LogEntry> & { id: string }): LogEntry {
  return {
    timestamp: new Date().toISOString(),
    level: 'INFO',
    component: 'engine',
    message: 'started',
    ...partial
  };
}

const emptyPage: QueryLogsResponse = {
  entries: [],
  truncated: false,
  availableDates: ['20261121', '20261122']
};

describe('LogsView filters and paging', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => cleanup());

  it('filters the live list by text, component and level', () => {
    const logs = [
      log({ id: '1', message: 'proxy connected', component: 'proxy' }),
      log({ id: '2', message: 'dns flushed', component: 'dns' }),
      log({ id: '3', message: 'proxy failed', component: 'proxy', level: 'ERROR' })
    ];
    render(<LogsView logs={logs} onClear={vi.fn()} />);
    expect(screen.getByText('proxy connected')).toBeInTheDocument();

    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'failed' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('logs.query.search_button') }));
    expect(screen.queryByText('proxy connected')).not.toBeInTheDocument();
    expect(screen.getByText('proxy failed')).toBeInTheDocument();

    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: i18n.t('logs.query.search_button') }));
    fireEvent.change(screen.getByLabelText(i18n.t('logs.query.component_label')), {
      target: { value: 'dns' }
    });
    expect(screen.getByText('dns flushed')).toBeInTheDocument();
    expect(screen.queryByText('proxy failed')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(i18n.t('logs.query.component_label')), {
      target: { value: '' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'ERROR' }));
    expect(screen.getByText('proxy failed')).toBeInTheDocument();
    expect(screen.queryByText('dns flushed')).not.toBeInTheDocument();
  });

  it('filters on the time range', () => {
    const old = log({ id: 'old', message: 'ancient', timestamp: '2020-01-01T00:00:00Z' });
    const fresh = log({ id: 'fresh', message: 'recent' });
    render(<LogsView logs={[old, fresh]} onClear={vi.fn()} />);
    fireEvent.change(screen.getByLabelText(i18n.t('logs.query.range_label')), {
      target: { value: String(UI_CONFIG.LOG_TIME_RANGE_MS.LAST_HOUR) }
    });
    expect(screen.queryByText('ancient')).not.toBeInTheDocument();
    expect(screen.getByText('recent')).toBeInTheDocument();
  });

  it('offers the daemon files by date and pages with the next cursor', async () => {
    const queries: QueryLogsRequest[] = [];
    const onQuery = vi.fn(async (req: QueryLogsRequest): Promise<QueryLogsResponse> => {
      queries.push(req);
      if (req.source === 'memory') return emptyPage;
      if (!req.cursor) {
        return { ...emptyPage, entries: [log({ id: 'f1', message: 'first page' })], truncated: true, nextCursor: 'cur-2' };
      }
      return { ...emptyPage, entries: [log({ id: 'f2', message: 'second page' })] };
    });
    render(<LogsView logs={[]} onClear={vi.fn()} onQuery={onQuery} />);
    const source = await screen.findByLabelText(i18n.t('logs.query.source_label'));
    await waitFor(() =>
      expect(
        within(source).getByRole('option', {
          name: i18n.t('logs.query.source_file', { date: '2026-11-22' })
        })
      ).toBeInTheDocument()
    );
    fireEvent.change(source, { target: { value: '20261122' } });
    expect(await screen.findByText('first page')).toBeInTheDocument();
    expect(queries.at(-1)?.source).toEqual({ daemonFile: { date: '20261122' } });

    fireEvent.click(screen.getByRole('button', { name: i18n.t('logs.query.load_more') }));
    expect(await screen.findByText('second page')).toBeInTheDocument();
    expect(screen.getByText('first page')).toBeInTheDocument();
    expect(queries.at(-1)?.cursor).toBe('cur-2');
    expect(screen.queryByRole('button', { name: i18n.t('logs.query.load_more') })).not.toBeInTheDocument();
  });

  it('opens pre-filtered on a connection with a window of 30 seconds', async () => {
    const center = Date.parse('2026-11-22T10:00:00Z');
    const logs = [
      log({
        id: 'in',
        message: 'inside window',
        timestamp: '2026-11-22T10:00:10Z',
        context: { connectionId: 'conn-1', pid: 42 }
      }),
      log({
        id: 'far',
        message: 'outside window',
        timestamp: '2026-11-22T10:05:00Z',
        context: { connectionId: 'conn-1', pid: 42 }
      }),
      log({
        id: 'other',
        message: 'other connection',
        timestamp: '2026-11-22T10:00:10Z',
        context: { connectionId: 'conn-2', pid: 7 }
      })
    ];
    render(
      <LogsView
        logs={logs}
        onClear={vi.fn()}
        jump={{ connectionId: 'conn-1', pid: 42, centerMs: center, nonce: 1 }}
      />
    );
    await waitFor(() => expect(screen.queryByText('other connection')).not.toBeInTheDocument());
    expect(screen.getByText('inside window')).toBeInTheDocument();
    expect(screen.queryByText('outside window')).not.toBeInTheDocument();
    expect(
      screen.getByText(i18n.t('logs.query.jump_active', { seconds: 30 }))
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: i18n.t('logs.query.jump_clear') }));
    expect(screen.getByText('outside window')).toBeInTheDocument();
    expect(screen.getByText('other connection')).toBeInTheDocument();
  });

  it('shows an alert when a daemon file cannot be read', async () => {
    const onQuery = vi.fn(async (req: QueryLogsRequest): Promise<QueryLogsResponse> => {
      if (req.source === 'memory') return emptyPage;
      throw new Error('boom');
    });
    render(<LogsView logs={[]} onClear={vi.fn()} onQuery={onQuery} />);
    const source = await screen.findByLabelText(i18n.t('logs.query.source_label'));
    await waitFor(() =>
      expect(within(source).getAllByRole('option').length).toBeGreaterThan(1)
    );
    fireEvent.change(source, { target: { value: '20261122' } });
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('logs.query.error'));
  });
});

describe('DiagnosticExportModal', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  const bundle: DiagnosticBundle = {
    manifest: {
      version: 1,
      os: 'windows',
      sections: [
        { name: 'system', bytes: 2048 },
        { name: 'logs', bytes: 3 * 1024 * 1024 }
      ],
      redactions: ['passwords', 'proxy usernames']
    },
    system: {},
    logs: []
  };

  it('warns about visited sites, then shows the manifest with sizes before download', async () => {
    const onCollect = vi.fn().mockResolvedValue(bundle);
    render(<DiagnosticExportModal onCollect={onCollect} onClose={vi.fn()} />);
    expect(screen.getByRole('note')).toHaveTextContent(i18n.t('diagnostics.export.sites_warning'));
    expect(screen.queryByRole('button', { name: i18n.t('diagnostics.export.download') })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    await screen.findByRole('button', { name: i18n.t('diagnostics.export.download') });
    expect(onCollect).toHaveBeenCalledWith({
      logDays: UI_CONFIG.DIAGNOSTIC_LOG_DAYS_DEFAULT,
      includeConnections: true,
      includeProfile: true,
      maskDomains: false
    });
    const table = screen.getByRole('table');
    expect(within(table).getByText(i18n.t('diagnostics.export.section.system'))).toBeInTheDocument();
    expect(within(table).getByText(i18n.t('diagnostics.export.section.logs'))).toBeInTheDocument();
    expect(within(table).getByText(/2[.,]0 /)).toBeInTheDocument();
    expect(
      screen.getByText(i18n.t('diagnostics.export.redactions', { list: 'passwords, proxy usernames' }))
    ).toBeInTheDocument();
  });

  it('asks for masked sites when the toggle is on and hides the warning', async () => {
    const onCollect = vi.fn().mockResolvedValue(bundle);
    render(<DiagnosticExportModal onCollect={onCollect} onClose={vi.fn()} />);
    fireEvent.click(screen.getByLabelText(i18n.t('diagnostics.export.mask_sites')));
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    await screen.findByRole('table');
    expect(onCollect.mock.calls[0][0].maskDomains).toBe(true);
  });

  it('forgets the prepared file when an option changes', async () => {
    const onCollect = vi.fn().mockResolvedValue(bundle);
    render(<DiagnosticExportModal onCollect={onCollect} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    await screen.findByRole('table');
    fireEvent.click(screen.getByLabelText(i18n.t('diagnostics.export.include_profile')));
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') })).toBeInTheDocument();
  });

  it('downloads the JSON with a dated file name', async () => {
    const createObjectURL = vi.fn(() => 'blob:test');
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const onDownloaded = vi.fn();
    render(
      <DiagnosticExportModal
        onCollect={vi.fn().mockResolvedValue(bundle)}
        onClose={vi.fn()}
        onDownloaded={onDownloaded}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    fireEvent.click(await screen.findByRole('button', { name: i18n.t('diagnostics.export.download') }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blob = (createObjectURL.mock.calls[0] as unknown as [Blob])[0];
    expect(blob.type).toBe('application/json');
    expect(JSON.parse(await blob.text()).manifest.version).toBe(1);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(onDownloaded.mock.calls[0][0]).toMatch(
      new RegExp(`^${UI_CONFIG.DIAGNOSTIC_FILE_PREFIX}\\d{8}-\\d{4}\\.json$`)
    );
    expect(revokeObjectURL).toHaveBeenCalled();
  });

  it('accepts a manifest that lists sections as a name to size record', async () => {
    const record: DiagnosticBundle = {
      manifest: { version: 1, sections: { profile: 512 } as never }
    };
    render(<DiagnosticExportModal onCollect={vi.fn().mockResolvedValue(record)} onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    expect(await screen.findByText(i18n.t('diagnostics.export.section.profile'))).toBeInTheDocument();
  });

  it('shows an alert when the file cannot be prepared and is a labelled dialog', async () => {
    render(
      <DiagnosticExportModal onCollect={vi.fn().mockRejectedValue(new Error('x'))} onClose={vi.fn()} />
    );
    expect(screen.getByRole('dialog')).toHaveAccessibleName(i18n.t('diagnostics.export.title'));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('diagnostics.export.error'));
  });
});

describe('AnalyzerPanel', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => cleanup());

  const findings: Finding[] = [
    {
      code: 'proxyUnreachable',
      severity: 'critical',
      subject: { proxyId: 'p1' },
      evidenceCount: 12,
      lastSeen: '2026-11-22T10:00:00Z',
      fix: { type: 'testProxy', id: 'p1' }
    },
    {
      code: 'quicOrDohBlockedInfo',
      severity: 'info',
      subject: {},
      evidenceCount: 5,
      fix: { type: 'none' }
    },
    {
      code: 'brandNewCode',
      severity: 'warning',
      subject: {},
      evidenceCount: 1,
      fix: { type: 'restartApp' }
    }
  ];
  const proxies = [
    {
      id: 'p1',
      name: 'Office proxy',
      protocol: 'socks5' as const,
      host: 'h',
      port: 1,
      auth: null,
      udpEnabled: true,
      tls: false,
      sni: null,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    }
  ];

  it('renders localized findings with the proxy name and a fix button when one exists', () => {
    const onFix = vi.fn();
    render(
      <AnalyzerPanel findings={findings} proxies={proxies} rules={[]} analyzed onRun={vi.fn()} onFix={onFix} />
    );
    expect(
      screen.getByText(i18n.t('analyzer.findings.proxyUnreachable.title', { proxy: 'Office proxy' }))
    ).toBeInTheDocument();
    expect(
      screen.getByText(i18n.t('analyzer.findings.proxyUnreachable.fix'))
    ).toBeInTheDocument();
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(3);
    fireEvent.click(within(items[0]).getByRole('button', { name: i18n.t('analyzer.action.test_proxy') }));
    expect(onFix).toHaveBeenCalledWith({ type: 'testProxy', id: 'p1' });
    expect(within(items[1]).queryByRole('button')).not.toBeInTheDocument();
    expect(within(items[2]).queryByRole('button')).not.toBeInTheDocument();
  });

  it('falls back to a generic text for a finding code it does not know', () => {
    render(
      <AnalyzerPanel findings={findings} proxies={proxies} rules={[]} analyzed onRun={vi.fn()} onFix={vi.fn()} />
    );
    expect(screen.getByText(i18n.t('analyzer.unknown.title'))).toBeInTheDocument();
  });

  it('says nothing was found only after an analysis, and runs on request', () => {
    const onRun = vi.fn();
    const { rerender } = render(
      <AnalyzerPanel findings={[]} proxies={[]} rules={[]} onRun={onRun} onFix={vi.fn()} />
    );
    expect(screen.queryByText(i18n.t('analyzer.none'))).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('analyzer.run') }));
    expect(onRun).toHaveBeenCalledTimes(1);
    rerender(<AnalyzerPanel findings={[]} proxies={[]} rules={[]} analyzed onRun={onRun} onFix={vi.fn()} />);
    expect(screen.getByText(i18n.t('analyzer.none'))).toBeInTheDocument();
  });

  it('disables the run button while checking and alerts on failure', () => {
    render(
      <AnalyzerPanel findings={[]} proxies={[]} rules={[]} loading error onRun={vi.fn()} onFix={vi.fn()} />
    );
    expect(screen.getByRole('button', { name: i18n.t('analyzer.running') })).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent(i18n.t('analyzer.error'));
  });
});

describe('locale coverage of analyzer findings', () => {
  it('has a title, body and fix for every documented finding code in both languages', () => {
    const codes = [
      'proxyUnreachable',
      'proxyAuthRejected',
      'defaultPolicyBlocking',
      'appBlockedBySimpleRule',
      'appBlockedByPack',
      'ruleShadowed',
      'quicOrDohBlockedInfo',
      'unattributedDropsHigh',
      'fakeIpGuardHits',
      'protectionPausedOrStopped',
      'logFolderLarge'
    ];
    for (const lng of ['en', 'fr']) {
      for (const code of codes) {
        for (const part of ['title', 'body', 'fix']) {
          expect(i18n.exists(`analyzer.findings.${code}.${part}`, { lng })).toBe(true);
        }
      }
    }
  });
});

describe('review fixes in the diagnostics screens', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => cleanup());

  it('renders the manifest redaction codes in plain words and keeps an unknown code as is', async () => {
    const codes = [
      'passwords',
      'authHeaders',
      'tokens',
      'urlSecrets',
      'userPaths',
      'usernames',
      'machineName',
      'exitIp',
      'domains'
    ];
    const bundle: DiagnosticBundle = {
      manifest: {
        version: 1,
        os: 'windows',
        sections: [{ name: 'system', bytes: 10 }],
        redactions: [...codes, 'brandNewRedaction']
      },
      system: {}
    };
    render(
      <DiagnosticExportModal onCollect={vi.fn().mockResolvedValue(bundle)} onClose={vi.fn()} />
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('diagnostics.export.prepare') }));
    await screen.findByRole('button', { name: i18n.t('diagnostics.export.download') });
    const expected = [
      ...codes.map((code) => i18n.t(`diagnostics.export.redaction.${code}`)),
      'brandNewRedaction'
    ].join(', ');
    for (const code of codes) {
      expect(i18n.exists(`diagnostics.export.redaction.${code}`)).toBe(true);
    }
    expect(
      screen.getByText(i18n.t('diagnostics.export.redactions', { list: expected }))
    ).toBeInTheDocument();
  });

  it('asks for a confirmation before the analyzer pauses protection', () => {
    const onFix = vi.fn();
    const findings: Finding[] = [
      {
        code: 'protectionPausedOrStopped',
        severity: 'warning',
        subject: {},
        evidenceCount: 1,
        fix: { type: 'pauseProtection' }
      }
    ];
    render(
      <AnalyzerPanel findings={findings} proxies={[]} rules={[]} analyzed onRun={vi.fn()} onFix={onFix} />
    );
    fireEvent.click(screen.getByRole('button', { name: i18n.t('analyzer.action.pause') }));
    expect(onFix).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('dashboard.confirm.cancel') }));
    expect(onFix).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('analyzer.action.pause') }));
    fireEvent.click(screen.getByRole('button', { name: i18n.t('dashboard.confirm.apply') }));
    expect(onFix).toHaveBeenCalledWith({ type: 'pauseProtection' });
  });
});
