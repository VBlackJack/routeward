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

import React, { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Info, RefreshCw, ShieldAlert, Stethoscope } from 'lucide-react';
import { describeBlockReason, isProxyOutageReason } from '../services/blockReason';
import { formatLogTime } from '../services/format';
import { getFriendlyAppName, localizeEngineRuleName } from '../services/friendly';
import {
  listUnblockOptions,
  UnblockDuration,
  UnblockOption,
  UnblockTarget
} from '../services/unblockPlan';
import {
  BlockedCounters,
  BlockedSummaryEntry,
  ProxyChain,
  ProxyNode,
  RoutingRule
} from '../types/routeward';
import { UnblockOptions } from './UnblockOptions';

interface BlockedViewProps {
  entries: BlockedSummaryEntry[];
  counters: BlockedCounters | null;
  rules: RoutingRule[];
  proxies: ProxyNode[];
  chains: ProxyChain[];
  loading?: boolean;
  /** True when the last refresh failed. */
  error?: boolean;
  onRefresh?: () => void;
  onChoose: (
    target: UnblockTarget,
    option: UnblockOption,
    duration: UnblockDuration
  ) => void;
  onSeeLogs: (entry: BlockedSummaryEntry) => void;
  onOpenCheckup?: () => void;
  /** Narrows the list to one app and destination (set by a check-up fix). */
  focus?: Partial<BlockedSummaryEntry> | null;
  onClearFocus?: () => void;
}

/** Entries that match the focus (app, then destination when given), or all of them if none do. */
export function applyBlockedFocus(
  entries: BlockedSummaryEntry[],
  focus?: Partial<BlockedSummaryEntry> | null
): { entries: BlockedSummaryEntry[]; focused: boolean } {
  if (!focus || (!focus.processName && !focus.destination)) {
    return { entries, focused: false };
  }
  const same = (a: string | undefined, b: string | undefined) =>
    !a || (b ?? '').toLowerCase() === a.toLowerCase();
  const matching = entries.filter(
    (e) => same(focus.processName, e.processName) && same(focus.destination, e.destination)
  );
  return matching.length > 0
    ? { entries: matching, focused: true }
    : { entries, focused: false };
}

interface AppGroup {
  key: string;
  processName: string;
  total: number;
  sites: BlockedSummaryEntry[];
}

function entryKey(entry: BlockedSummaryEntry): string {
  return [
    entry.processName,
    entry.destination,
    entry.targetPort,
    entry.protocol,
    entry.blockReason,
    entry.matchedRuleId ?? ''
  ].join('|');
}

/** Groups the daemon summary by application, then by destination, busiest first. */
export function groupBlockedEntries(entries: BlockedSummaryEntry[]): AppGroup[] {
  const map = new Map<string, AppGroup>();
  for (const entry of entries) {
    const key = entry.processName.toLowerCase();
    const group = map.get(key) ?? {
      key,
      processName: entry.processName,
      total: 0,
      sites: []
    };
    group.total += entry.count;
    group.sites.push(entry);
    map.set(key, group);
  }
  const groups = Array.from(map.values());
  for (const group of groups) {
    group.sites.sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
  }
  return groups.sort((a, b) => b.total - a.total);
}

/** The "Blocked" tab of Activity: what was blocked, why in plain words, and how to unblock it. */
export const BlockedView: React.FC<BlockedViewProps> = ({
  entries,
  counters,
  rules,
  proxies,
  chains,
  loading = false,
  error = false,
  onRefresh,
  onChoose,
  onSeeLogs,
  onOpenCheckup,
  focus = null,
  onClearFocus
}) => {
  const { t } = useTranslation();
  const [openKey, setOpenKey] = useState<string | null>(null);
  const focused = useMemo(() => applyBlockedFocus(entries, focus), [entries, focus]);
  const groups = useMemo(() => groupBlockedEntries(focused.entries), [focused.entries]);
  const unattributed =
    (counters?.droppedUnattributedSyn ?? 0) + (counters?.droppedUnattributedUdp ?? 0);

  return (
    <div className="space-y-4">
      <div className="tf-card flex flex-wrap items-start justify-between gap-3 p-5">
        <div>
          <h2 className="text-base font-bold text-tf-primary">{t('blocked.title')}</h2>
          <p className="mt-1 text-xs text-tf-secondary">{t('blocked.subtitle')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {onOpenCheckup && (
            <button
              type="button"
              onClick={onOpenCheckup}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
            >
              <Stethoscope className="h-3.5 w-3.5" />
              {t('blocked.checkup')}
            </button>
          )}
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-secondary hover:text-tf-primary"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              {t('blocked.refresh')}
            </button>
          )}
        </div>
      </div>

      {error && (
        <p role="alert" className="text-xs text-tf-red">
          {t('blocked.error')}
        </p>
      )}

      {focused.focused && (
        <div className="flex flex-wrap items-center gap-3 text-xs text-tf-secondary">
          <span>{t('blocked.focus.notice')}</span>
          {onClearFocus && (
            <button
              type="button"
              onClick={onClearFocus}
              className="tf-surface-alt px-3 py-1 text-xs font-semibold text-tf-primary hover:border-tf-accent"
            >
              {t('blocked.focus.clear')}
            </button>
          )}
        </div>
      )}

      {groups.length === 0 ? (
        <div className="tf-card p-6 text-center text-xs text-tf-secondary">
          {t('blocked.empty')}
        </div>
      ) : (
        <div className="space-y-3">
          {groups.map((group) => {
            const friendly = getFriendlyAppName(group.processName);
            return (
              <section
                key={group.key}
                aria-label={friendly.displayName}
                className="tf-card space-y-3 p-4"
              >
                <header className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-tf-orange" />
                  <h3 className="text-sm font-bold text-tf-primary">
                    {friendly.displayName}
                  </h3>
                  {friendly.technicalName && (
                    <span className="rounded bg-tf-surface-alt px-1.5 py-0.5 font-mono text-[10px] text-tf-secondary">
                      {friendly.technicalName}
                    </span>
                  )}
                  <span className="rounded bg-tf-surface-alt px-2 py-0.5 text-[11px] font-medium text-tf-secondary">
                    {t('blocked.row.count', { count: group.total })}
                  </span>
                </header>
                <ul className="space-y-3">
                  {group.sites.map((entry) => {
                    const key = entryKey(entry);
                    const info = describeBlockReason(entry.blockReason, entry.lastErrorDetail);
                    const proxyName =
                      proxies.find((p) => p.id === entry.proxyId)?.name ??
                      entry.proxyId ??
                      '';
                    const target: UnblockTarget = {
                      processName: entry.processName,
                      processPath: entry.processPath,
                      destination: entry.destination,
                      targetPort: entry.targetPort,
                      protocol: entry.protocol,
                      blockReason: entry.blockReason,
                      matchedRuleId: entry.matchedRuleId,
                      proxyId: entry.proxyId
                    };
                    const open = openKey === key;
                    return (
                      <li
                        key={key}
                        className="space-y-2 border-t border-tf-border pt-3 first:border-t-0 first:pt-0"
                      >
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0 space-y-1">
                            <div className="break-all font-mono text-xs font-semibold text-tf-primary">
                              {entry.destination}:{entry.targetPort}
                            </div>
                            <div
                              className={`text-xs font-semibold ${
                                info.severity === 'critical'
                                  ? 'text-tf-red'
                                  : info.severity === 'warning'
                                    ? 'text-tf-orange'
                                    : 'text-tf-cyan'
                              }`}
                            >
                              {t(info.titleKey)}
                            </div>
                            <p className="text-xs text-tf-secondary">
                              {t(info.bodyKey, {
                                proxy: proxyName,
                                rule: entry.matchedRule
                                  ? localizeEngineRuleName(entry.matchedRule, t)
                                  : ''
                              })}
                            </p>
                            <div className="flex flex-wrap gap-x-3 text-[11px] text-tf-secondary">
                              {entry.matchedRule && (
                                <span>
                                  {t('blocked.row.rule', {
                                    name: localizeEngineRuleName(entry.matchedRule, t)
                                  })}
                                </span>
                              )}
                              {proxyName && isProxyOutageReason(entry.blockReason) && (
                                <span>{t('blocked.row.proxy', { name: proxyName })}</span>
                              )}
                              <span>
                                {t('blocked.row.last_seen', {
                                  time: formatLogTime(entry.lastSeen)
                                })}
                              </span>
                              <span>{t('blocked.row.count', { count: entry.count })}</span>
                            </div>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              aria-expanded={open}
                              onClick={() => setOpenKey(open ? null : key)}
                              className="tf-btn-accent px-3 py-1.5 text-xs font-bold"
                            >
                              {t('blocked.row.unblock')}
                            </button>
                            <button
                              type="button"
                              onClick={() => onSeeLogs(entry)}
                              className="tf-surface-alt px-3 py-1.5 text-xs font-semibold text-tf-secondary hover:text-tf-primary"
                            >
                              {t('blocked.row.see_logs')}
                            </button>
                          </div>
                        </div>
                        {open && (
                          <UnblockOptions
                            options={listUnblockOptions(target, {
                              rules,
                              proxies,
                              chains,
                              t
                            })}
                            explanation={t(info.bodyKey, { proxy: proxyName, rule: '' })}
                            onChoose={(option, duration) => {
                              onChoose(target, option, duration);
                              setOpenKey(null);
                            }}
                          />
                        )}
                      </li>
                    );
                  })}
                </ul>
              </section>
            );
          })}
        </div>
      )}

      <div className="flex items-start gap-2 rounded-tf-md border border-tf-border bg-tf-surface-alt p-3 text-[11px] text-tf-secondary">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-tf-cyan" />
        <div className="space-y-1">
          {unattributed > 0 && (
            <p className="font-semibold text-tf-primary">
              {t('blocked.counters.line', {
                syn: counters?.droppedUnattributedSyn ?? 0,
                udp: counters?.droppedUnattributedUdp ?? 0
              })}
            </p>
          )}
          <p>{t('blocked.counters.limit')}</p>
        </div>
      </div>
    </div>
  );
};
