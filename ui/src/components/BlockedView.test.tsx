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
import {
  BlockedSummaryEntry,
  PreviewRuleChangeResponse,
  RoutingRule
} from '../types/routeward';
import { BlockedShortcut } from './BlockedShortcut';
import { applyBlockedFocus, BlockedView, groupBlockedEntries } from './BlockedView';
import { useUnblockFlow } from './useUnblockFlow';

function makeEntry(partial: Partial<BlockedSummaryEntry>): BlockedSummaryEntry {
  return {
    processName: 'chrome.exe',
    processPath: 'C:/chrome.exe',
    destination: 'example.com',
    targetPort: 443,
    protocol: 'tcp',
    blockReason: 'ruleBlock',
    matchedRuleId: 'rule-app-chrome-exe',
    matchedRule: 'Chrome blocked',
    count: 3,
    firstSeen: '2026-11-22T09:00:00Z',
    lastSeen: '2026-11-22T10:00:00Z',
    lastConnectionId: 'conn-1',
    lastPid: 42,
    ...partial
  };
}

const simpleRule: RoutingRule = {
  id: 'rule-app-chrome-exe',
  name: 'Chrome blocked',
  enabled: true,
  priority: 15,
  processPatterns: ['chrome.exe'],
  domainPatterns: [],
  ipCidrs: [],
  portRanges: [],
  protocol: 'any',
  action: { type: 'block' }
};

describe('BlockedView', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => {
    cleanup();
  });

  const baseProps = {
    counters: null,
    rules: [simpleRule],
    proxies: [],
    chains: [],
    onChoose: vi.fn(),
    onSeeLogs: vi.fn()
  };

  it('groups entries by app, then by site, busiest app first', () => {
    const groups = groupBlockedEntries([
      makeEntry({ processName: 'slack.exe', destination: 'a.example', count: 1 }),
      makeEntry({ destination: 'b.example', lastSeen: '2026-11-22T10:05:00Z' }),
      makeEntry({ destination: 'c.example', lastSeen: '2026-11-22T10:01:00Z' }),
      makeEntry({ processName: 'Chrome.exe', destination: 'd.example', count: 2 })
    ]);
    expect(groups.map((g) => g.key)).toEqual(['chrome.exe', 'slack.exe']);
    expect(groups[0].total).toBe(8);
    expect(groups[0].sites.map((s) => s.destination)).toEqual([
      'b.example',
      'c.example',
      'd.example'
    ]);
  });

  it('shows the reason in plain words, the rule, the count and the buttons', () => {
    render(
      <BlockedView
        {...baseProps}
        entries={[makeEntry({})]}
      />
    );
    const section = screen.getByRole('region', { name: 'Google Chrome' });
    expect(within(section).getByText('example.com:443')).toBeInTheDocument();
    expect(
      within(section).getByText(i18n.t('blocked.reasons.ruleBlock.title'))
    ).toBeInTheDocument();
    expect(
      within(section).getByText(i18n.t('blocked.reasons.ruleBlock.body'))
    ).toBeInTheDocument();
    expect(
      within(section).getByText(i18n.t('blocked.row.rule', { name: 'Chrome blocked' }))
    ).toBeInTheDocument();
    expect(within(section).getAllByText(i18n.t('blocked.row.count', { count: 3 })).length).toBeGreaterThan(0);
    expect(within(section).getByRole('button', { name: 'Unblock' })).toBeInTheDocument();
    expect(within(section).getByRole('button', { name: 'See logs' })).toBeInTheDocument();
  });

  it('opens the options and reports the chosen option with its duration', () => {
    const onChoose = vi.fn();
    render(
      <BlockedView
        {...baseProps}
        onChoose={onChoose}
        entries={[makeEntry({})]}
      />
    );
    const unblock = screen.getByRole('button', { name: 'Unblock' });
    expect(unblock).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(unblock);
    expect(unblock).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(screen.getByLabelText(i18n.t('unblock.duration.minutes15')));
    fireEvent.click(
      screen.getByRole('button', {
        name: new RegExp(i18n.t('unblock.option.exception_app_direct.title').replace(/[()]/g, '\\$&'))
      })
    );
    expect(onChoose).toHaveBeenCalledTimes(1);
    const [target, option, duration] = onChoose.mock.calls[0];
    expect(target.processName).toBe('chrome.exe');
    expect(target.matchedRuleId).toBe('rule-app-chrome-exe');
    expect(option.kind).toBe('exceptionApp');
    expect(duration).toBe('minutes15');
  });

  it('narrows the list to the focused app and destination, with a way back', () => {
    const onClearFocus = vi.fn();
    const entries = [
      makeEntry({ destination: 'a.example' }),
      makeEntry({ destination: 'b.example' }),
      makeEntry({ processName: 'slack.exe', destination: 'a.example' })
    ];
    render(
      <BlockedView
        {...baseProps}
        entries={entries}
        focus={{ processName: 'Chrome.exe', destination: 'b.example' }}
        onClearFocus={onClearFocus}
      />
    );
    expect(screen.getByText('b.example:443')).toBeInTheDocument();
    expect(screen.queryByText('a.example:443')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: i18n.t('blocked.focus.clear') }));
    expect(onClearFocus).toHaveBeenCalled();
  });

  it('shows everything when the focus matches nothing', () => {
    const entries = [makeEntry({ destination: 'a.example' })];
    expect(applyBlockedFocus(entries, { processName: 'other.exe' })).toEqual({
      entries,
      focused: false
    });
    expect(applyBlockedFocus(entries, null).focused).toBe(false);
    expect(applyBlockedFocus(entries, { processName: 'chrome.exe' }).focused).toBe(true);
  });

  it('shows only an explanation for a QUIC block', () => {
    render(
      <BlockedView
        {...baseProps}
        entries={[makeEntry({ blockReason: 'quicBlocked', matchedRuleId: undefined })]}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Unblock' }));
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    expect(
      screen.getAllByText(i18n.t('blocked.reasons.quicBlocked.body')).length
    ).toBeGreaterThanOrEqual(2);
  });

  it('asks for the logs of the last connection of an entry', () => {
    const onSeeLogs = vi.fn();
    const entry = makeEntry({});
    render(<BlockedView {...baseProps} onSeeLogs={onSeeLogs} entries={[entry]} />);
    fireEvent.click(screen.getByRole('button', { name: 'See logs' }));
    expect(onSeeLogs).toHaveBeenCalledWith(entry);
  });

  it('shows the empty message and always states the known limit', () => {
    render(<BlockedView {...baseProps} entries={[]} />);
    expect(screen.getByText(i18n.t('blocked.empty'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('blocked.counters.limit'))).toBeInTheDocument();
  });

  it('shows the unattributed counters as an info line', () => {
    render(
      <BlockedView
        {...baseProps}
        entries={[]}
        counters={{ droppedUnattributedSyn: 4, droppedUnattributedUdp: 9 }}
      />
    );
    expect(
      screen.getByText(i18n.t('blocked.counters.line', { syn: 4, udp: 9 }))
    ).toBeInTheDocument();
  });

  it('falls back to the generic text for a reason it does not know', () => {
    render(
      <BlockedView
        {...baseProps}
        entries={[makeEntry({ blockReason: 'brandNew' as never, lastErrorDetail: 'proxy timed out' })]}
      />
    );
    expect(screen.getByText(i18n.t('blocked.reasons.unknown.title'))).toBeInTheDocument();
    expect(screen.getByText(i18n.t('troubleshoot.reasons.timeout'))).toBeInTheDocument();
  });

  it('shows an alert when the list could not be loaded', () => {
    render(<BlockedView {...baseProps} entries={[]} error />);
    expect(screen.getByRole('alert')).toHaveTextContent(i18n.t('blocked.error'));
  });
});

describe('BlockedShortcut', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => cleanup());

  it('appears only when something was blocked and opens the Blocked tab', () => {
    const onOpen = vi.fn();
    const { rerender } = render(<BlockedShortcut blockedCount={0} onOpen={onOpen} />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    rerender(<BlockedShortcut blockedCount={2} onOpen={onOpen} />);
    fireEvent.click(screen.getByRole('button', { name: i18n.t('blocked.home.cta') }));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});

describe('unblock flow with preview, confirmation and undo', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => cleanup());

  function Harness(props: {
    preview: PreviewRuleChangeResponse | null;
    upsertRule: (rule: RoutingRule) => Promise<unknown>;
    removeRule: (id: string) => Promise<unknown>;
    notify: (
      message: string,
      severity: string,
      action?: { label: string; onAction: () => void }
    ) => void;
    previewRuleChange: (req: unknown) => Promise<PreviewRuleChangeResponse | null>;
  }) {
    const flow = useUnblockFlow({
      rules: [simpleRule],
      proxies: [],
      chains: [],
      t: (key, options) => i18n.t(key, options) as string,
      previewRuleChange: props.previewRuleChange,
      upsertRule: props.upsertRule,
      removeRule: props.removeRule,
      onCommand: vi.fn(),
      notify: props.notify as never,
      onError: vi.fn()
    });
    return (
      <>
        <BlockedView
          entries={[makeEntry({})]}
          counters={null}
          rules={[simpleRule]}
          proxies={[]}
          chains={[]}
          onChoose={(target, option, duration) => {
            void flow.choose(target, option, duration);
          }}
          onSeeLogs={vi.fn()}
        />
        {flow.element}
      </>
    );
  }

  const directOutcome: PreviewRuleChangeResponse = {
    evaluation: {
      matchedRuleId: 'rule-unblock-app-chrome-exe',
      matchedRuleName: 'Chrome direct',
      action: { type: 'direct' },
      effectiveDomain: 'example.com',
      resolvedFromFakeIp: false
    }
  };

  async function openExceptionConfirmation(
    preview: PreviewRuleChangeResponse | null,
    duration: 'minutes15' | 'always' = 'always'
  ) {
    const upsertRule = vi.fn().mockResolvedValue(undefined);
    const removeRule = vi.fn().mockResolvedValue(undefined);
    const notify = vi.fn();
    const previewRuleChange = vi.fn().mockResolvedValue(preview);
    render(
      <Harness
        preview={preview}
        upsertRule={upsertRule}
        removeRule={removeRule}
        notify={notify}
        previewRuleChange={previewRuleChange}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Unblock' }));
    fireEvent.click(screen.getByLabelText(i18n.t(`unblock.duration.${duration}`)));
    fireEvent.click(
      screen.getByRole('button', {
        name: new RegExp(i18n.t('unblock.option.exception_app_direct.title').replace(/[()]/g, '\\$&'))
      })
    );
    await screen.findByRole('dialog');
    return { upsertRule, removeRule, notify, previewRuleChange };
  }

  it('previews the change, shows the diff and predicted outcome, then applies it', async () => {
    const { upsertRule, previewRuleChange } = await openExceptionConfirmation(directOutcome);
    expect(previewRuleChange).toHaveBeenCalledTimes(1);
    const request = previewRuleChange.mock.calls[0][0] as {
      upserts: RoutingRule[];
      request: { processName: string; targetHost: string };
    };
    expect(request.upserts[0].id).toBe('rule-unblock-app-chrome-exe');
    expect(request.request.targetHost).toBe('example.com');
    const dialog = screen.getByRole('dialog');
    expect(
      within(dialog).getByText(i18n.t('unblock.confirm.outcome_direct'))
    ).toBeInTheDocument();
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: i18n.t('dashboard.confirm.apply') }));
    await waitFor(() => expect(upsertRule).toHaveBeenCalledTimes(1));
    expect(upsertRule.mock.calls[0][0].action).toEqual({ type: 'direct' });
  });

  it('warns when a security policy would still block the connection', async () => {
    await openExceptionConfirmation({
      evaluation: { ...directOutcome.evaluation, action: { type: 'proxy', targetId: 'p1' } },
      policyOverride: 'killSwitchProxyUnreachable'
    });
    const alert = within(screen.getByRole('dialog')).getByRole('alert');
    expect(alert).toHaveTextContent(i18n.t('blocked.reasons.killSwitchProxyUnreachable.title'));
  });

  it('still asks for confirmation when the preview is unavailable', async () => {
    await openExceptionConfirmation(null);
    expect(
      within(screen.getByRole('dialog')).getByText(i18n.t('unblock.confirm.outcome_unknown'))
    ).toBeInTheDocument();
  });

  it('does not apply anything when the confirmation is cancelled', async () => {
    const { upsertRule } = await openExceptionConfirmation(directOutcome);
    fireEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: i18n.t('dashboard.confirm.cancel')
      })
    );
    expect(upsertRule).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('offers an undo that removes the exception it created', async () => {
    const { upsertRule, removeRule, notify } = await openExceptionConfirmation(directOutcome);
    fireEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: i18n.t('dashboard.confirm.apply')
      })
    );
    await waitFor(() => expect(notify).toHaveBeenCalled());
    expect(upsertRule).toHaveBeenCalledTimes(1);
    const action = notify.mock.calls[0][2] as { label: string; onAction: () => void };
    expect(action.label).toBe(i18n.t('app.toast.undo'));
    action.onAction();
    await waitFor(() => expect(removeRule).toHaveBeenCalledWith('rule-unblock-app-chrome-exe'));
  });

  it('creates a temporary exception with an expiry for 15 minutes', async () => {
    const { upsertRule } = await openExceptionConfirmation(directOutcome, 'minutes15');
    fireEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: i18n.t('dashboard.confirm.apply')
      })
    );
    await waitFor(() => expect(upsertRule).toHaveBeenCalled());
    expect(typeof upsertRule.mock.calls[0][0].expiresAt).toBe('string');
  });
});
