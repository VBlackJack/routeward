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

import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  ArrowRight,
  Copy,
  FileCode2,
  Link2,
  Lock,
  Plus,
  Server,
  Trash2,
  Zap
} from 'lucide-react';
import { UI_CONFIG } from '../config/constants';
import { routewardClient } from '../services/ipc';
import {
  ChainStrategy,
  ProxyChain,
  ProxyNode,
  ProxyProtocol
} from '../types/routeward';

interface ProxiesViewProps {
  proxies: ProxyNode[];
  chains: ProxyChain[];
  onTestProxy: (id: string) => Promise<void>;
  onTestAllProxies: () => Promise<void>;
  onAddProxy: (node: ProxyNode) => void;
  onImportUris: (uriLines: string) => void;
  onCopyUri: (uri: string) => void;
  onRemoveProxy: (id: string) => void;
  onAddChain: (chain: ProxyChain) => void;
  onRemoveChain: (id: string) => void;
}

const PROTOCOLS: ProxyProtocol[] = ['socks5', 'http', 'https'];

const STRATEGIES: ChainStrategy[] = [
  'sequence',
  'failover',
  'lowest_latency',
  'load_balance'
];

export const ProxiesView: React.FC<ProxiesViewProps> = ({
  proxies,
  chains,
  onTestProxy,
  onTestAllProxies,
  onAddProxy,
  onImportUris,
  onCopyUri,
  onRemoveProxy,
  onAddChain,
  onRemoveChain
}) => {
  const { t } = useTranslation();
  const [testingId, setTestingId] = useState<string | null>(null);
  const [showAddProxy, setShowAddProxy] = useState(false);
  const [showImportUri, setShowImportUri] = useState(false);
  const [showAddChain, setShowAddChain] = useState(false);

  // Add Proxy state
  const [name, setName] = useState('');
  const [protocol, setProtocol] = useState<ProxyProtocol>('socks5');
  const [host, setHost] = useState('127.0.0.1');
  const [port, setPort] = useState<number>(UI_CONFIG.DEFAULT_PROXY_PORT);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [udpEnabled, setUdpEnabled] = useState(true);
  const [tls, setTls] = useState(false);

  // Import URI state
  const [uriBatchText, setUriBatchText] = useState('');

  // Add Chain state
  const [chainName, setChainName] = useState('');
  const [chainStrategy, setChainStrategy] =
    useState<ChainStrategy>('sequence');
  const [selectedHops, setSelectedHops] = useState<string[]>([]);

  const handleSingleTest = async (id: string) => {
    setTestingId(id);
    await onTestProxy(id);
    setTestingId(null);
  };

  const handleCreateProxy = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !host.trim()) return;
    onAddProxy({
      id: `proxy-${Date.now()}`,
      name: name.trim(),
      protocol,
      host: host.trim(),
      port,
      auth:
        username || password
          ? { username: username.trim(), password }
          : null,
      udpEnabled,
      tls,
      sni: tls ? host.trim() : null,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    });
    setName('');
    setShowAddProxy(false);
  };

  const handleBatchUriSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!uriBatchText.trim()) return;
    onImportUris(uriBatchText);
    setUriBatchText('');
    setShowImportUri(false);
  };

  const handleCreateChain = (e: React.FormEvent) => {
    e.preventDefault();
    if (!chainName.trim() || selectedHops.length === 0) return;
    onAddChain({
      id: `chain-${Date.now()}`,
      name: chainName.trim(),
      strategy: chainStrategy,
      proxyIds: selectedHops,
      enabled: true
    });
    setChainName('');
    setSelectedHops([]);
    setShowAddChain(false);
  };

  const handleCopyNodeUri = (node: ProxyNode) => {
    const uri = routewardClient.formatProxyUri(node);
    if (navigator.clipboard) {
      navigator.clipboard.writeText(uri).catch(() => {});
    }
    onCopyUri(uri);
  };

  return (
    <div className="space-y-8">
      {/* Upstream Proxy Servers */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-base font-bold text-tf-primary">
            {t('proxies.section.servers.title')}
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={onTestAllProxies}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-tf-cyan hover:border-tf-cyan"
            >
              <Activity className="h-3.5 w-3.5" />
              {t('proxies.section.servers.test_all')}
            </button>
            <button
              onClick={() => setShowImportUri(true)}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-tf-primary hover:border-tf-accent"
            >
              <FileCode2 className="h-3.5 w-3.5 text-tf-accent" />
              {t('proxies.section.servers.import_uri')}
            </button>
            <button
              onClick={() => setShowAddProxy(true)}
              className="tf-btn-accent flex items-center gap-1.5 px-3.5 py-1.5 text-xs"
            >
              <Plus className="h-3.5 w-3.5" />
              {t('proxies.section.servers.add')}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {proxies.map((proxy) => (
            <div
              key={proxy.id}
              className="tf-card flex flex-col justify-between p-4"
            >
              <div>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-tf-accent" />
                    <span className="font-bold text-tf-primary">
                      {proxy.name}
                    </span>
                  </div>
                  <span className="rounded bg-tf-surface-alt px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-tf-accent">
                    {proxy.protocol}
                  </span>
                </div>

                <div className="mt-2 font-mono text-xs text-tf-secondary">
                  {proxy.host}:{proxy.port}
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5 text-[10px]">
                  <span
                    className={`rounded px-2 py-0.5 font-semibold ${
                      proxy.udpEnabled
                        ? 'bg-tf-cyan/20 text-tf-cyan'
                        : 'bg-tf-surface-alt text-tf-secondary'
                    }`}
                  >
                    {proxy.udpEnabled
                      ? t('proxies.card.badge.udp_ready')
                      : t('proxies.card.badge.tcp_only')}
                  </span>
                  {proxy.tls && (
                    <span className="flex items-center gap-1 rounded bg-tf-green/20 px-2 py-0.5 font-semibold text-tf-green">
                      <Lock className="h-2.5 w-2.5" />
                      {t('proxies.card.badge.tls_enabled')}
                    </span>
                  )}
                  {proxy.lastLatencyMs !== null ? (
                    <span className="rounded bg-tf-green/20 px-2 py-0.5 font-mono font-bold text-tf-green">
                      {proxy.lastLatencyMs} ms
                    </span>
                  ) : (
                    <span className="rounded bg-tf-surface-alt px-2 py-0.5 text-tf-secondary">
                      {t('proxies.card.badge.untested')}
                    </span>
                  )}
                </div>

                {proxy.exitIp && (
                  <div className="mt-2 font-mono text-[11px] text-tf-secondary">
                    {t('proxies.card.badge.exit_ip')}:{' '}
                    <span className="text-tf-primary">{proxy.exitIp}</span>
                  </div>
                )}
              </div>

              <div className="mt-4 flex items-center justify-between border-t border-tf-border pt-3">
                <button
                  onClick={() => handleSingleTest(proxy.id)}
                  disabled={testingId === proxy.id}
                  className="flex items-center gap-1 text-xs font-semibold text-tf-accent hover:underline"
                >
                  <Zap className="h-3.5 w-3.5" />
                  {testingId === proxy.id
                    ? t('proxies.card.action.testing')
                    : t('proxies.card.action.test')}
                </button>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyNodeUri(proxy)}
                    className="flex items-center gap-1 text-xs text-tf-secondary hover:text-tf-primary"
                    title={t('proxies.card.action.copy_uri')}
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={() => onRemoveProxy(proxy.id)}
                    className="text-xs text-tf-secondary hover:text-tf-red"
                    title={t('proxies.card.action.delete')}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Smart Proxy Chains & Failover Groups */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-tf-primary">
              {t('proxies.section.chains.title')}
            </h2>
            <p className="text-xs text-tf-secondary">
              {t('proxies.section.chains.subtitle')}
            </p>
          </div>
          <button
            onClick={() => setShowAddChain(true)}
            className="tf-btn-accent flex items-center gap-1.5 px-3.5 py-1.5 text-xs"
          >
            <Plus className="h-3.5 w-3.5" />
            {t('proxies.section.chains.add')}
          </button>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {chains.map((chain) => {
            const strat = chain.strategy || 'sequence';
            return (
              <div key={chain.id} className="tf-card p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Link2 className="h-4 w-4 text-tf-pink" />
                    <div>
                      <span className="font-bold text-tf-primary">
                        {chain.name}
                      </span>
                      <div className="text-[11px] text-tf-secondary">
                        {t(`proxies.strategy.mode.${strat}`)}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-tf-pink/20 px-2 py-0.5 text-[10px] font-bold text-tf-pink">
                      {chain.proxyIds.length}{' '}
                      {t('proxies.section.chains.hops')}
                    </span>
                    <button
                      onClick={() => onRemoveChain(chain.id)}
                      className="text-tf-secondary hover:text-tf-red"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {chain.proxyIds.map((pid, idx) => {
                    const node = proxies.find((p) => p.id === pid);
                    return (
                      <React.Fragment key={`${pid}-${idx}`}>
                        <span className="tf-surface-alt px-2.5 py-1 font-mono text-xs text-tf-primary">
                          {node ? node.name : pid}
                          {node?.lastLatencyMs
                            ? ` (${node.lastLatencyMs}ms)`
                            : ''}
                        </span>
                        {idx < chain.proxyIds.length - 1 && (
                          <ArrowRight className="h-3.5 w-3.5 text-tf-accent" />
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Batch Import URI Modal */}
      {showImportUri && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <form
            onSubmit={handleBatchUriSubmit}
            className="tf-card w-full max-w-lg space-y-4 p-6"
          >
            <div>
              <h3 className="text-base font-bold text-tf-primary">
                {t('proxies.modal.import_uri.title')}
              </h3>
              <p className="mt-1 text-xs text-tf-secondary">
                {t('proxies.modal.import_uri.subtitle')}
              </p>
            </div>
            <textarea
              rows={5}
              required
              value={uriBatchText}
              onChange={(e) => setUriBatchText(e.target.value)}
              placeholder={t('proxies.modal.import_uri.placeholder')}
              className="tf-input w-full p-3 font-mono text-xs"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowImportUri(false)}
                className="tf-surface-alt px-4 py-1.5 text-xs text-tf-secondary"
              >
                {t('proxies.modal.import_uri.cancel')}
              </button>
              <button
                type="submit"
                className="tf-btn-accent px-4 py-1.5 text-xs"
              >
                {t('proxies.modal.import_uri.submit')}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Add Proxy Modal */}
      {showAddProxy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <form
            onSubmit={handleCreateProxy}
            className="tf-card w-full max-w-md space-y-4 p-6"
          >
            <h3 className="text-base font-bold text-tf-primary">
              {t('proxies.modal.add_proxy.title')}
            </h3>
            <div>
              <label className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_proxy.name_label')}
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.protocol_label')}
                </label>
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value as ProxyProtocol)}
                  className="tf-input mt-1 w-full px-2 py-1.5 text-sm uppercase"
                >
                  {PROTOCOLS.map((p) => (
                    <option key={p} value={p}>
                      {p.toUpperCase()}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.host_label')}
                </label>
                <input
                  type="text"
                  required
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.port_label')}
                </label>
                <input
                  type="number"
                  required
                  value={port}
                  onChange={(e) => setPort(Number(e.target.value))}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.username_label')}
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.password_label')}
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>
            <div className="flex items-center gap-6 pt-1 text-xs text-tf-primary">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={udpEnabled}
                  onChange={(e) => setUdpEnabled(e.target.checked)}
                />
                {t('proxies.modal.add_proxy.udp_label')}
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={tls}
                  onChange={(e) => setTls(e.target.checked)}
                />
                {t('proxies.modal.add_proxy.tls_label')}
              </label>
            </div>
            <div className="flex justify-end gap-2 pt-3">
              <button
                type="button"
                onClick={() => setShowAddProxy(false)}
                className="tf-surface-alt px-4 py-1.5 text-xs text-tf-secondary"
              >
                {t('proxies.modal.add_proxy.cancel')}
              </button>
              <button
                type="submit"
                className="tf-btn-accent px-4 py-1.5 text-xs"
              >
                {t('proxies.modal.add_proxy.submit')}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Add Chain / Smart Group Modal */}
      {showAddChain && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <form
            onSubmit={handleCreateChain}
            className="tf-card w-full max-w-md space-y-4 p-6"
          >
            <h3 className="text-base font-bold text-tf-primary">
              {t('proxies.modal.add_chain.title')}
            </h3>
            <div>
              <label className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_chain.name_label')}
              </label>
              <input
                type="text"
                required
                value={chainName}
                onChange={(e) => setChainName(e.target.value)}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_chain.strategy_label')}
              </label>
              <select
                value={chainStrategy}
                onChange={(e) =>
                  setChainStrategy(e.target.value as ChainStrategy)
                }
                className="tf-input mt-1 w-full px-3 py-1.5 text-xs"
              >
                {STRATEGIES.map((st) => (
                  <option key={st} value={st}>
                    {t(`proxies.strategy.mode.${st}`)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_chain.select_hop')}
              </label>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {proxies.map((p) => (
                  <button
                    type="button"
                    key={p.id}
                    onClick={() => setSelectedHops((prev) => [...prev, p.id])}
                    className="tf-surface-alt px-2.5 py-1 text-xs text-tf-primary hover:border-tf-accent"
                  >
                    + {p.name}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_chain.sequence_label')}
              </label>
              <div className="tf-surface-alt mt-1 flex min-h-[42px] flex-wrap items-center gap-1.5 p-2 text-xs">
                {selectedHops.map((id, i) => {
                  const p = proxies.find((x) => x.id === id);
                  return (
                    <span
                      key={`${id}-${i}`}
                      className="rounded bg-tf-accent/20 px-2 py-0.5 font-mono text-tf-accent"
                    >
                      {i + 1}. {p?.name || id}
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-3">
              <button
                type="button"
                onClick={() => setShowAddChain(false)}
                className="tf-surface-alt px-4 py-1.5 text-xs text-tf-secondary"
              >
                {t('proxies.modal.add_chain.cancel')}
              </button>
              <button
                type="submit"
                className="tf-btn-accent px-4 py-1.5 text-xs"
              >
                {t('proxies.modal.add_chain.submit')}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
