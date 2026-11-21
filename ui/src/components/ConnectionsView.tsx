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
import {
  Ban,
  CheckCircle,
  Download,
  Globe,
  PowerOff,
  Radar,
  Search,
  Server,
  Shield,
  Terminal,
  Trash2,
  X
} from 'lucide-react';
import { formatBytes, generateClientId } from '../services/ipc';
import {
  getFriendlyAppName,
  resolveSimpleProxyAction
} from '../services/friendly';
import {
  ConnectionStatus,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  TrackedConnection
} from '../types/routeward';
import { ExperienceMode } from './QuickSetupWizardModal';

interface ConnectionsViewProps {
  connections: TrackedConnection[];
  proxies: ProxyNode[];
  chains?: ProxyChain[];
  experienceMode?: ExperienceMode;
  engineRunning?: boolean;
  onEnableProtection?: () => void;
  onScanOsSockets: () => void;
  onClearClosed: () => void;
  onTerminateConnection: (connectionId: string) => void;
  onQuickCreateRule: (rule: RoutingRule) => void;
  onMissingProxy?: () => void;
  onSwitchToExpert?: () => void;
  onExportActivity?: (format: 'csv' | 'json') => void;
}

const QUICK_RULE_HIGH_PRIORITY = 8;

type SimpleActivityFilter = 'all' | 'proxied' | 'blocked';

interface AppActivityGroup {
  processName: string;
  count: number;
  totalBytes: number;
  domains: string[];
  routeKind: 'proxied' | 'blocked' | 'direct';
  routeLabel: string;
  sampleConn: TrackedConnection;
}

export const ConnectionsView: React.FC<ConnectionsViewProps> = ({
  connections,
  proxies,
  chains = [],
  experienceMode = 'expert',
  engineRunning = true,
  onEnableProtection,
  onScanOsSockets,
  onClearClosed,
  onTerminateConnection,
  onQuickCreateRule,
  onMissingProxy,
  onSwitchToExpert,
  onExportActivity
}) => {
  const { t } = useTranslation();
  const [filterText, setFilterText] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | ConnectionStatus>(
    'all'
  );
  const [simpleFilter, setSimpleFilter] = useState<SimpleActivityFilter>('all');
  const [selectedConnId, setSelectedConnId] = useState<string | null>(null);

  const groupedApps = useMemo<AppActivityGroup[]>(() => {
    const q = filterText.trim().toLowerCase();
    const map = new Map<string, AppActivityGroup>();

    for (const conn of connections) {
      const domainOrHost = conn.resolvedDomain || conn.targetHost;
      const key = conn.processName.toLowerCase();
      const existing = map.get(key);
      const isBlocked = conn.status === 'blocked';
      const isDirect = conn.routeLabel.toLowerCase().includes('direct');
      const connKind: AppActivityGroup['routeKind'] = isBlocked
        ? 'blocked'
        : isDirect
          ? 'direct'
          : 'proxied';

      if (!existing) {
        map.set(key, {
          processName: conn.processName,
          count: 1,
          totalBytes: conn.rxBytes + conn.txBytes,
          domains: domainOrHost ? [domainOrHost] : [],
          routeKind: connKind,
          routeLabel: conn.routeLabel,
          sampleConn: conn
        });
      } else {
        existing.count += 1;
        existing.totalBytes += conn.rxBytes + conn.txBytes;
        if (
          domainOrHost &&
          existing.domains.length < 3 &&
          !existing.domains.includes(domainOrHost)
        ) {
          existing.domains.push(domainOrHost);
        }
        if (connKind === 'blocked' && existing.routeKind !== 'blocked') {
          existing.routeKind = 'blocked';
        } else if (connKind === 'proxied' && existing.routeKind === 'direct') {
          existing.routeKind = 'proxied';
        }
      }
    }

    return Array.from(map.values()).filter((group) => {
      if (simpleFilter === 'proxied' && group.routeKind !== 'proxied') {
        return false;
      }
      if (simpleFilter === 'blocked' && group.routeKind !== 'blocked') {
        return false;
      }
      if (!q) return true;
      return (
        group.processName.toLowerCase().includes(q) ||
        group.domains.some((d) => d.toLowerCase().includes(q))
      );
    });
  }, [connections, filterText, simpleFilter]);

  const selectedConnection = useMemo(
    () => connections.find((c) => c.id === selectedConnId) || null,
    [connections, selectedConnId]
  );

  const filtered = useMemo(() => {
    const q = filterText.trim().toLowerCase();
    return connections.filter((c) => {
      if (statusFilter !== 'all' && c.status !== statusFilter) {
        return false;
      }
      if (!q) return true;
      return (
        c.processName.toLowerCase().includes(q) ||
        c.targetHost.toLowerCase().includes(q) ||
        (c.resolvedDomain && c.resolvedDomain.toLowerCase().includes(q)) ||
        c.matchedRule.toLowerCase().includes(q) ||
        c.routeLabel.toLowerCase().includes(q)
      );
    });
  }, [connections, filterText, statusFilter]);

  const buildQuickProcessRule = (
    conn: TrackedConnection,
    actionType: 'proxy' | 'direct' | 'block'
  ) => {
    const simpleProxyAction = resolveSimpleProxyAction(proxies, chains);
    if (actionType === 'proxy' && !simpleProxyAction) {
      onMissingProxy?.();
      return;
    }
    onQuickCreateRule({
      id: generateClientId('rule-quick'),
      name: `${conn.processName} (${actionType.toUpperCase()})`,
      enabled: true,
      priority: QUICK_RULE_HIGH_PRIORITY,
      processPatterns: [conn.processName],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action:
        actionType === 'proxy' && simpleProxyAction
          ? simpleProxyAction
          : { type: actionType === 'proxy' ? 'direct' : actionType }
    });
  };

  const buildQuickDomainBlockRule = (conn: TrackedConnection) => {
    const domain = conn.resolvedDomain || conn.targetHost;
    onQuickCreateRule({
      id: generateClientId('rule-domain'),
      name: `Block ${domain}`,
      enabled: true,
      priority: QUICK_RULE_HIGH_PRIORITY,
      processPatterns: [],
      domainPatterns: [domain],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action: { type: 'block' }
    });
  };

  const escapeCsvCell = (raw: string | number | null | undefined): string => {
    const str = String(raw ?? '');
    const neutralized = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
    return `"${neutralized.replace(/"/g, '""')}"`;
  };

  const handleExportActivity = (format: 'csv' | 'json') => {
    const content =
      format === 'json'
        ? JSON.stringify(filtered, null, 2)
        : [
            [
              'startedAt',
              'pid',
              'processName',
              'processPath',
              'targetHost',
              'resolvedDomain',
              'targetPort',
              'protocol',
              'matchedRule',
              'routeLabel',
              'status',
              'latencyMs',
              'rxBytes',
              'txBytes',
              'errorDetail'
            ].join(','),
            ...filtered.map((c) =>
              [
                c.startedAt,
                c.pid,
                c.processName,
                c.processPath,
                c.targetHost,
                c.resolvedDomain || '',
                c.targetPort,
                c.protocol,
                c.matchedRule,
                c.routeLabel,
                c.status,
                c.latencyMs,
                c.rxBytes,
                c.txBytes,
                c.errorDetail || ''
              ]
                .map(escapeCsvCell)
                .join(',')
            )
          ].join('\n');

    const mime =
      format === 'json' ? 'application/json' : 'text/csv;charset=utf-8';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `routeward-activity.${format}`;
    a.click();
    URL.revokeObjectURL(url);
    onExportActivity?.(format);
  };

  if (experienceMode === 'simple') {
    return (
      <div className="space-y-4">
        <div className="tf-card p-5">
          <h2 className="text-base font-bold text-tf-primary">
            {t('connections.simple.title')}
          </h2>
          <p className="mt-1 text-xs text-tf-secondary">
            {t('connections.simple.subtitle')}
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative min-w-[240px] flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-tf-secondary" />
            <input name="connections-simple-filter"
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder={t('connections.simple.search_placeholder')}
              aria-label={t('connections.simple.search_placeholder')}
              className="tf-input w-full py-2 pl-9 pr-4 text-sm"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {(
              [
                { id: 'all' as const, label: t('connections.simple.filter_all') },
                {
                  id: 'proxied' as const,
                  label: t('connections.simple.filter_proxied')
                },
                {
                  id: 'blocked' as const,
                  label: t('connections.simple.filter_blocked')
                }
              ]
            ).map((chip) => (
              <button
                key={chip.id}
                type="button"
                aria-pressed={simpleFilter === chip.id}
                onClick={() => setSimpleFilter(chip.id)}
                className={`rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                  simpleFilter === chip.id
                    ? 'bg-tf-accent text-tf-bg'
                    : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                }`}
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>

        {groupedApps.length === 0 ? (
          <div className="tf-card flex flex-col items-center gap-3 p-6 text-center text-xs text-tf-secondary">
            <span>{t('connections.simple.no_apps')}</span>
            {!engineRunning && onEnableProtection ? (
              <button
                type="button"
                onClick={onEnableProtection}
                className="tf-btn-accent px-4 py-2 text-xs font-bold"
              >
                {t('connections.simple.empty_paused_cta')}
              </button>
            ) : (
              <button
                type="button"
                onClick={onScanOsSockets}
                className="tf-surface-alt flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
              >
                <Radar className="h-3.5 w-3.5" />
                {t('connections.simple.empty_refresh_cta')}
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-2.5">
            {groupedApps.map((group) => {
              const friendly = getFriendlyAppName(group.processName);
              return (
                <div
                  key={group.processName}
                  className="tf-card flex flex-wrap items-center justify-between gap-4 p-4"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-bold text-tf-primary">
                        {friendly.displayName}
                      </span>
                      {friendly.technicalName && (
                        <span className="rounded bg-tf-surface-alt px-1.5 py-0.5 font-mono text-[10px] text-tf-secondary">
                          {friendly.technicalName}
                        </span>
                      )}
                      <span className="rounded bg-tf-surface-alt px-2 py-0.5 text-[11px] font-medium text-tf-secondary">
                        {t('connections.simple.count_connections', {
                          count: group.count
                        })}
                      </span>
                      <span className="font-mono text-[11px] text-tf-cyan">
                        {formatBytes(group.totalBytes)}
                      </span>
                    </div>
                    <div className="text-xs text-tf-secondary">
                      {group.domains.join(', ')}
                    </div>
                  </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    aria-pressed={group.routeKind === 'proxied'}
                    onClick={() =>
                      buildQuickProcessRule(group.sampleConn, 'proxy')
                    }
                    className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                      group.routeKind === 'proxied'
                        ? 'bg-tf-accent text-tf-bg'
                        : 'tf-surface-alt text-tf-accent hover:border-tf-accent'
                    }`}
                  >
                    <Server className="h-3.5 w-3.5" />
                    {t('connections.simple.route_proxy')}
                  </button>
                  <button
                    type="button"
                    aria-pressed={group.routeKind === 'direct'}
                    onClick={() =>
                      buildQuickProcessRule(group.sampleConn, 'direct')
                    }
                    className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                      group.routeKind === 'direct'
                        ? 'bg-tf-green text-tf-bg'
                        : 'tf-surface-alt text-tf-green hover:border-tf-green'
                    }`}
                  >
                    <CheckCircle className="h-3.5 w-3.5" />
                    {t('connections.simple.route_direct')}
                  </button>
                  <button
                    type="button"
                    aria-pressed={group.routeKind === 'blocked'}
                    onClick={() =>
                      buildQuickProcessRule(group.sampleConn, 'block')
                    }
                    className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                      group.routeKind === 'blocked'
                        ? 'bg-tf-red text-tf-bg'
                        : 'tf-surface-alt text-tf-red hover:border-tf-red'
                    }`}
                  >
                    <Ban className="h-3.5 w-3.5" />
                    {t('connections.simple.route_blocked')}
                  </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {onSwitchToExpert && (
          <div className="flex justify-center pt-2">
            <button
              type="button"
              onClick={onSwitchToExpert}
              className="tf-surface-alt flex items-center gap-2 px-4 py-2 text-xs font-medium text-tf-secondary hover:border-tf-cyan hover:text-tf-cyan"
            >
              <Terminal className="h-3.5 w-3.5" />
              {t('connections.simple.switch_expert_cta')}
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative min-w-[260px] flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-tf-secondary" />
          <input name="connections-filter"
            type="text"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder={t('connections.toolbar.search.placeholder')}
            aria-label={t('connections.toolbar.search.placeholder')}
            className="tf-input w-full py-2 pl-9 pr-4 text-sm"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {(['all', 'active', 'blocked', 'closed'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`rounded-tf-md px-2.5 py-1.5 text-xs font-semibold transition ${
                statusFilter === st
                  ? 'bg-tf-accent text-tf-bg'
                  : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
              }`}
            >
              {t(`connections.toolbar.status_filter.${st}`)}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => handleExportActivity('csv')}
            className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs text-tf-primary hover:border-tf-accent"
          >
            <Download className="h-3.5 w-3.5" />
            {t('connections.toolbar.export_csv')}
          </button>
          <button
            type="button"
            onClick={() => handleExportActivity('json')}
            className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs text-tf-primary hover:border-tf-accent"
          >
            <Download className="h-3.5 w-3.5" />
            {t('connections.toolbar.export_json')}
          </button>
          <button
            onClick={onScanOsSockets}
            className="tf-surface-alt flex items-center gap-2 border-tf-cyan/60 px-3 py-2 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
          >
            <Radar className="h-3.5 w-3.5" />
            {t('connections.toolbar.scan_os.button')}
          </button>
          <button
            onClick={onClearClosed}
            className="tf-surface-alt flex items-center gap-1.5 px-3 py-2 text-xs text-tf-secondary hover:text-tf-primary"
          >
            <Trash2 className="h-3.5 w-3.5" />
            {t('connections.toolbar.clear.button')}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div
          className={`tf-card overflow-hidden ${
            selectedConnection ? 'lg:col-span-2' : 'lg:col-span-3'
          }`}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-tf-border bg-tf-surface-alt text-[11px] uppercase tracking-wider text-tf-secondary">
                <tr>
                  <th className="px-4 py-3">
                    {t('connections.table.process.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.target.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.protocol.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.rule.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.route.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.latency.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.traffic.header')}
                  </th>
                  <th className="px-4 py-3">
                    {t('connections.table.status.header')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-tf-border">
                {filtered.length === 0 ? (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-4 py-8 text-center text-tf-secondary"
                    >
                      {t('connections.table.empty.message')}
                    </td>
                  </tr>
                ) : (
                  filtered.map((conn) => {
                    const isSelected = conn.id === selectedConnId;
                    return (
                      <tr
                        key={conn.id}
                        onClick={() => setSelectedConnId(conn.id)}
                        onKeyDown={(e) => {
                          if (
                            e.target === e.currentTarget &&
                            (e.key === 'Enter' || e.key === ' ')
                          ) {
                            e.preventDefault();
                            setSelectedConnId(conn.id);
                          }
                        }}
                        tabIndex={0}
                        aria-current={isSelected ? 'true' : undefined}
                        className={`cursor-pointer transition ${
                          isSelected
                            ? 'bg-tf-surface-alt'
                            : 'hover:bg-tf-surface-alt/50'
                        }`}
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Terminal className="h-4 w-4 text-tf-accent" />
                            <div>
                              <div className="font-semibold text-tf-primary">
                                {conn.processName}{' '}
                                <span className="font-mono text-[11px] text-tf-secondary">
                                  ({conn.pid})
                                </span>
                              </div>
                              <div className="max-w-[180px] truncate text-[10px] text-tf-secondary">
                                {conn.processPath}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3 font-mono">
                          <div className="text-tf-primary">
                            {conn.targetHost}:{conn.targetPort}
                          </div>
                          {conn.resolvedDomain &&
                            conn.resolvedDomain !== conn.targetHost && (
                              <div className="text-[10px] text-tf-cyan">
                                Fake-IP → {conn.resolvedDomain}
                              </div>
                            )}
                        </td>
                        <td className="px-4 py-3 uppercase text-tf-secondary">
                          {conn.protocol}
                        </td>
                        <td className="px-4 py-3 font-medium text-tf-primary">
                          {conn.matchedRule}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-tf-sm px-2 py-0.5 font-mono text-[11px] font-semibold ${
                              conn.status === 'blocked'
                                ? 'bg-tf-red/20 text-tf-red'
                                : conn.routeLabel === 'DIRECT'
                                  ? 'bg-tf-green/20 text-tf-green'
                                  : 'bg-tf-accent/20 text-tf-accent'
                            }`}
                          >
                            {conn.routeLabel}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-tf-secondary">
                          {conn.latencyMs > 0 ? `${conn.latencyMs} ms` : '-'}
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px]">
                          <span className="text-tf-cyan">
                            ↓ {formatBytes(conn.rxBytes)}
                          </span>{' '}
                          /{' '}
                          <span className="text-tf-pink">
                            ↑ {formatBytes(conn.txBytes)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold ${
                              conn.status === 'active'
                                ? 'bg-tf-green/20 text-tf-green'
                                : conn.status === 'blocked'
                                  ? 'bg-tf-red/20 text-tf-red'
                                  : 'bg-tf-surface-alt text-tf-secondary'
                            }`}
                          >
                            {t(`connections.table.status.${conn.status}`)}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Interactive Connection Inspector Drawer */}
        {selectedConnection && (
          <div className="tf-card flex flex-col justify-between p-5">
            <div className="space-y-4">
              <div className="flex items-start justify-between border-b border-tf-border pb-3">
                <div>
                  <h3 className="text-sm font-bold text-tf-primary">
                    {t('connections.inspector.drawer.title')}
                  </h3>
                  <p className="text-[11px] text-tf-secondary">
                    {t('connections.inspector.drawer.subtitle')}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedConnId(null)}
                  aria-label={t('connections.inspector.drawer.close')}
                  className="rounded p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="space-y-2 text-xs">
                <div className="text-[10px] font-bold uppercase tracking-wider text-tf-accent">
                  {t('connections.inspector.drawer.process_section')}
                </div>
                <div className="tf-surface-alt space-y-1 p-3 font-mono text-[11px]">
                  <div>
                    <span className="text-tf-secondary">
                      {t('connections.inspector.drawer.executable_label')}:{' '}
                    </span>
                    <span className="font-bold text-tf-primary">
                      {selectedConnection.processName}
                    </span>
                  </div>
                  <div>
                    <span className="text-tf-secondary">
                      {t('connections.inspector.drawer.pid_label')}:{' '}
                    </span>
                    <span className="text-tf-cyan">
                      {selectedConnection.pid}
                    </span>
                  </div>
                  <div className="break-all">
                    <span className="text-tf-secondary">
                      {t('connections.inspector.drawer.path_label')}:{' '}
                    </span>
                    <span className="text-tf-primary">
                      {selectedConnection.processPath}
                    </span>
                  </div>
                </div>
              </div>

              <div className="space-y-2 text-xs">
                <div className="text-[10px] font-bold uppercase tracking-wider text-tf-accent">
                  {t('connections.inspector.drawer.destination_section')}
                </div>
                <div className="tf-surface-alt space-y-1 p-3 font-mono text-[11px]">
                  <div>
                    <span className="text-tf-secondary">
                      {t('connections.inspector.drawer.remote_endpoint')}:{' '}
                    </span>
                    <span className="font-bold text-tf-primary">
                      {selectedConnection.targetHost}:
                      {selectedConnection.targetPort}
                    </span>
                  </div>
                  {selectedConnection.resolvedDomain && (
                    <div>
                      <span className="text-tf-secondary">
                        {t('connections.inspector.drawer.resolved_domain')}:{' '}
                      </span>
                      <span className="text-tf-cyan">
                        {selectedConnection.resolvedDomain}
                      </span>
                    </div>
                  )}
                  <div>
                    <span className="text-tf-secondary">
                      {t('connections.inspector.drawer.matched_rule')}:{' '}
                    </span>
                    <span className="text-tf-green">
                      {selectedConnection.matchedRule}
                    </span>
                  </div>
                  {selectedConnection.errorDetail && (
                    <div className="mt-2 rounded border border-tf-red/40 bg-tf-red/10 p-2 text-tf-red break-words">
                      <div className="text-[10px] font-bold uppercase">
                        {t('connections.inspector.drawer.error_detail')}
                      </div>
                      <div className="mt-0.5 text-[11px]">
                        {selectedConnection.errorDetail}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* 1-Click Quick Rule Creation */}
              <div className="space-y-2 pt-1">
                <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-tf-accent">
                  <Shield className="h-3.5 w-3.5" />
                  <span>
                    {t('connections.inspector.drawer.quick_actions_title')}
                  </span>
                </div>
                <div className="grid grid-cols-1 gap-2">
                  <button
                    onClick={() =>
                      buildQuickProcessRule(selectedConnection, 'proxy')
                    }
                    className="tf-btn-accent flex items-center justify-center gap-2 py-2 text-xs"
                  >
                    <Server className="h-3.5 w-3.5" />
                    {t('connections.inspector.drawer.route_process_proxy')}
                  </button>
                  <button
                    onClick={() =>
                      buildQuickProcessRule(selectedConnection, 'direct')
                    }
                    className="tf-surface-alt flex items-center justify-center gap-2 py-2 text-xs font-semibold text-tf-green hover:border-tf-green"
                  >
                    <CheckCircle className="h-3.5 w-3.5" />
                    {t('connections.inspector.drawer.route_process_direct')}
                  </button>
                  <button
                    onClick={() =>
                      buildQuickProcessRule(selectedConnection, 'block')
                    }
                    className="tf-surface-alt flex items-center justify-center gap-2 py-2 text-xs font-semibold text-tf-red hover:border-tf-red"
                  >
                    <Ban className="h-3.5 w-3.5" />
                    {t('connections.inspector.drawer.block_process')}
                  </button>
                  <button
                    onClick={() => buildQuickDomainBlockRule(selectedConnection)}
                    className="tf-surface-alt flex items-center justify-center gap-2 py-2 text-xs font-semibold text-tf-orange hover:border-tf-orange"
                  >
                    <Globe className="h-3.5 w-3.5" />
                    {t('connections.inspector.drawer.block_domain')}
                  </button>
                </div>
              </div>
            </div>

            {selectedConnection.status === 'active' && (
              <div className="mt-4 border-t border-tf-border pt-3">
                <button
                  onClick={() => onTerminateConnection(selectedConnection.id)}
                  className="flex w-full items-center justify-center gap-2 rounded-tf-md border border-tf-red bg-tf-red/15 py-2 text-xs font-bold text-tf-red hover:bg-tf-red/25"
                >
                  <PowerOff className="h-3.5 w-3.5" />
                  {t('connections.inspector.drawer.terminate_socket')}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
