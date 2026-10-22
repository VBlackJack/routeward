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
  Globe,
  Play,
  PowerOff,
  Radar,
  Search,
  Server,
  Shield,
  Terminal,
  Trash2,
  X
} from 'lucide-react';
import { UI_CONFIG } from '../config/constants';
import { formatBytes } from '../services/ipc';
import {
  ConnectionRequest,
  ConnectionStatus,
  ProxyNode,
  RoutingRule,
  TrackedConnection
} from '../types/proxifier';

interface ConnectionsViewProps {
  connections: TrackedConnection[];
  proxies: ProxyNode[];
  onSimulate: (req: ConnectionRequest) => void;
  onScanOsSockets: () => void;
  onClearClosed: () => void;
  onTerminateConnection: (connectionId: string) => void;
  onQuickCreateRule: (rule: RoutingRule) => void;
}

const QUICK_RULE_HIGH_PRIORITY = 8;

export const ConnectionsView: React.FC<ConnectionsViewProps> = ({
  connections,
  proxies,
  onSimulate,
  onScanOsSockets,
  onClearClosed,
  onTerminateConnection,
  onQuickCreateRule
}) => {
  const { t } = useTranslation();
  const [filterText, setFilterText] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | ConnectionStatus>(
    'all'
  );
  const [presetIdx, setPresetIdx] = useState(0);
  const [selectedConnId, setSelectedConnId] = useState<string | null>(null);

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

  const handleSimulateClick = () => {
    const preset =
      UI_CONFIG.SIMULATION_PRESETS[
        presetIdx % UI_CONFIG.SIMULATION_PRESETS.length
      ];
    setPresetIdx((prev) => prev + 1);
    onSimulate(preset);
  };

  const buildQuickProcessRule = (
    conn: TrackedConnection,
    actionType: 'proxy' | 'direct' | 'block'
  ) => {
    const primaryProxyId = proxies[0]?.id || 'proxy-socks5-primary';
    onQuickCreateRule({
      id: `rule-quick-${Date.now()}`,
      name: `${conn.processName} (${actionType.toUpperCase()})`,
      enabled: true,
      priority: QUICK_RULE_HIGH_PRIORITY,
      processPatterns: [conn.processName],
      domainPatterns: [],
      ipCidrs: [],
      portRanges: [],
      protocol: 'any',
      action:
        actionType === 'proxy'
          ? { type: 'proxy', targetId: primaryProxyId }
          : { type: actionType }
    });
  };

  const buildQuickDomainBlockRule = (conn: TrackedConnection) => {
    const domain = conn.resolvedDomain || conn.targetHost;
    onQuickCreateRule({
      id: `rule-domain-${Date.now()}`,
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

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative min-w-[260px] flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-tf-secondary" />
          <input
            type="text"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder={t('connections.toolbar.search.placeholder')}
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

        <div className="flex items-center gap-2">
          <button
            onClick={onScanOsSockets}
            className="tf-surface-alt flex items-center gap-2 border-tf-cyan/60 px-3 py-2 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
          >
            <Radar className="h-3.5 w-3.5" />
            {t('connections.toolbar.scan_os.button')}
          </button>
          <button
            onClick={handleSimulateClick}
            className="tf-btn-accent flex items-center gap-2 px-4 py-2 text-xs"
          >
            <Play className="h-3.5 w-3.5" />
            {t('connections.toolbar.simulate.button')}
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
                          {conn.latencyMs > 0 ? `${conn.latencyMs} ms` : '—'}
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
                  onClick={() => setSelectedConnId(null)}
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
