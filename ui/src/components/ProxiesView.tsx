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

import React, { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  ClipboardPaste,
  Copy,
  Edit3,
  Eye,
  EyeOff,
  FileCode2,
  KeyRound,
  Link2,
  Lock,
  Plus,
  Power,
  Radar,
  Server,
  Star,
  X,
  Zap
} from 'lucide-react';
import { ModalContainer } from './ModalContainer';
import { ConfirmDeleteButton } from './ConfirmDeleteButton';
import { ExperienceMode } from './QuickSetupWizardModal';
import { UI_CONFIG } from '../config/constants';
import { generateClientId, routewardClient } from '../services/ipc';
import {
  normalizeProxyImportText,
  parseLooseProxyLink,
  planProxyRemoval,
  splitHostAndPort
} from '../services/friendly';
import {
  ChainStrategy,
  DetectedProxyCandidate,
  ProxyChain,
  ProxyNode,
  ProxyProtocol,
  RoutingRule
} from '../types/routeward';

interface ProxiesViewProps {
  proxies: ProxyNode[];
  chains: ProxyChain[];
  rules?: RoutingRule[];
  /** Ids of proxies whose last connection test failed (the daemon keeps no failure flag). */
  unreachableProxyIds?: string[];
  experienceMode?: ExperienceMode;
  onDetectExistingProxies?: () => Promise<DetectedProxyCandidate[]>;
  onTestProxy: (id: string) => Promise<void>;
  onTestAllProxies: () => Promise<void>;
  onAddProxy: (node: ProxyNode) => void;
  onImportUris: (uriLines: string) => void;
  onCopyUri: (uri: string) => void;
  onRemoveProxy: (id: string) => void;
  onAddChain: (chain: ProxyChain) => void;
  onRemoveChain: (id: string) => void;
  onToggleSimpleFailover?: (
    enabled: boolean,
    chain: ProxyChain | null
  ) => Promise<void> | void;
  onSetPrimaryProxy?: (proxyId: string) => Promise<void> | void;
  onPasteFromClipboard?: () => Promise<void> | void;
}

const PROTOCOLS: ProxyProtocol[] = ['socks5', 'socks4', 'http', 'https'];

const STRATEGIES: ChainStrategy[] = [
  'sequence',
  'failover',
  'lowest_latency',
  'load_balance'
];

export const ProxiesView: React.FC<ProxiesViewProps> = ({
  proxies,
  chains,
  rules = [],
  unreachableProxyIds = [],
  experienceMode = 'expert',
  onDetectExistingProxies,
  onTestProxy,
  onTestAllProxies,
  onAddProxy,
  onImportUris,
  onCopyUri,
  onRemoveProxy,
  onAddChain,
  onRemoveChain,
  onToggleSimpleFailover,
  onSetPrimaryProxy,
  onPasteFromClipboard
}) => {
  const { t } = useTranslation();
  const enabledProxies = proxies.filter((p) => p.enabled);
  const primaryProxyId = enabledProxies[0]?.id ?? null;
  // Only the chain this screen created is managed here: an Expert chain is never adopted.
  const simpleFailoverChain = chains.find(
    (c) => c.id === UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID
  );
  const simpleFailoverEnabled = Boolean(simpleFailoverChain?.enabled);

  const handleToggleSimpleFailover = () => {
    if (simpleFailoverEnabled && simpleFailoverChain) {
      if (onToggleSimpleFailover) {
        void onToggleSimpleFailover(false, simpleFailoverChain);
      } else {
        onRemoveChain(simpleFailoverChain.id);
      }
      return;
    }
    if (enabledProxies.length < 2) return;
    const nextChain: ProxyChain = {
      id: UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID,
      name: t('proxies.simple.failover_chain_name'),
      strategy: 'failover',
      proxyIds: enabledProxies.map((p) => p.id),
      enabled: true
    };
    if (onToggleSimpleFailover) {
      void onToggleSimpleFailover(true, nextChain);
    } else {
      onAddChain(nextChain);
    }
  };
  const importTitleId = useId();
  const proxyTitleId = useId();
  const chainTitleId = useId();
  const formId = useId();
  const [testingId, setTestingId] = useState<string | null>(null);
  const [detectingProxies, setDetectingProxies] = useState(false);
  const [detectedCandidates, setDetectedCandidates] = useState<
    DetectedProxyCandidate[] | null
  >(null);
  const [detectFailed, setDetectFailed] = useState(false);
  const [armedDeleteId, setArmedDeleteId] = useState<string | null>(null);
  const [showAddProxy, setShowAddProxy] = useState(false);
  const [showImportUri, setShowImportUri] = useState(false);
  const [showAddChain, setShowAddChain] = useState(false);
  const [showProtocolOptions, setShowProtocolOptions] = useState(false);

  // Add / Edit Proxy state
  const [editingProxyId, setEditingProxyId] = useState<string | null>(null);
  const [existingHasPassword, setExistingHasPassword] = useState(false);
  const [replacingPassword, setReplacingPassword] = useState(true);
  const [quickPasteText, setQuickPasteText] = useState('');
  const [quickPasteApplied, setQuickPasteApplied] = useState(false);
  const [name, setName] = useState('');
  const [protocol, setProtocol] = useState<ProxyProtocol>('socks5');
  const [host, setHost] = useState('');
  const [portInput, setPortInput] = useState<string>(
    String(UI_CONFIG.DEFAULT_PROXY_PORT)
  );
  const [portTouched, setPortTouched] = useState(false);
  const [protocolTouched, setProtocolTouched] = useState(false);
  const [quickPasteInvalid, setQuickPasteInvalid] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [portError, setPortError] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [udpEnabled, setUdpEnabled] = useState(true);
  const [tls, setTls] = useState(false);
  const [tlsSkipVerify, setTlsSkipVerify] = useState(false);

  // Import URI state
  const [uriBatchText, setUriBatchText] = useState('');

  // Add Chain state
  const [chainName, setChainName] = useState('');
  const [chainStrategy, setChainStrategy] =
    useState<ChainStrategy>('sequence');
  const [selectedHops, setSelectedHops] = useState<string[]>([]);

  const handleDetectExisting = async () => {
    if (detectingProxies) return;
    setDetectingProxies(true);
    setDetectFailed(false);
    try {
      const detector =
        onDetectExistingProxies ??
        (() => routewardClient.detectExistingProxiesStrict());
      const found = await detector();
      setDetectedCandidates(found);
    } catch {
      // A failed search is not "no proxy found": say so.
      setDetectedCandidates(null);
      setDetectFailed(true);
    } finally {
      setDetectingProxies(false);
    }
  };

  const handleImportDetectedCandidate = (cand: DetectedProxyCandidate) => {
    const effectiveTls = cand.protocol === 'https';
    onAddProxy({
      id: generateClientId('proxy'),
      name: cand.name,
      protocol: cand.protocol,
      host: cand.host,
      port: cand.port,
      auth: null,
      udpEnabled: cand.protocol === 'socks5',
      tls: effectiveTls,
      tlsSkipVerify: false,
      sni: effectiveTls ? cand.host : null,
      enabled: true,
      lastLatencyMs: null,
      exitIp: null
    });
    setDetectedCandidates((prev) =>
      prev
        ? prev.filter(
            (item) =>
              !(
                item.protocol === cand.protocol &&
                item.host === cand.host &&
                item.port === cand.port
              )
          )
        : null
    );
  };

  const handleSingleTest = async (id: string) => {
    setTestingId(id);
    await onTestProxy(id);
    setTestingId(null);
  };

  const applyParsedLinkToForm = (raw: string): boolean => {
    const trimmed = raw.trim();
    const parsed = parseLooseProxyLink(
      trimmed,
      protocolTouched ? protocol : UI_CONFIG.DEFAULT_LINK_PROXY_PROTOCOL
    );
    if (!parsed) return false;
    setName((prev) => (prev.trim() ? prev : parsed.name));
    setProtocol(parsed.protocol);
    setHost(parsed.host);
    setPortInput(String(parsed.port));
    setPortTouched(true);
    setPortError(null);
    setUsername(parsed.auth?.username || '');
    if (parsed.auth?.password) {
      setReplacingPassword(true);
      setPassword(parsed.auth.password);
    } else if (!editingProxyId) {
      setPassword('');
    }
    setUdpEnabled(parsed.udpEnabled);
    setTls(parsed.tls);
    setTlsSkipVerify(Boolean(parsed.tlsSkipVerify));
    setQuickPasteApplied(true);
    setQuickPasteInvalid(false);
    return true;
  };

  /** Parses the link field once the user is done typing (paste, Enter or leaving the field). */
  const commitQuickPaste = (value: string) => {
    if (!value.trim()) {
      setQuickPasteInvalid(false);
      return;
    }
    if (applyParsedLinkToForm(value)) {
      setQuickPasteText('');
    } else {
      setQuickPasteInvalid(true);
    }
  };

  /** Splits `host:port` or a full link typed in the host field. */
  const resolveHostField = (value: string): { host: string; port: number | null } => {
    const split = splitHostAndPort(value);
    return split ? { host: split.host, port: split.port } : { host: value, port: null };
  };

  const commitHostField = (value: string) => {
    if (value.includes('://')) {
      applyParsedLinkToForm(value);
      return;
    }
    const resolved = resolveHostField(value);
    if (resolved.port !== null) {
      setHost(resolved.host);
      setPortInput(String(resolved.port));
      setPortTouched(true);
      setPortError(null);
    }
  };

  const handleProtocolChange = (next: ProxyProtocol) => {
    setProtocol(next);
    setProtocolTouched(true);
    if (!portTouched && !editingProxyId) {
      setPortInput(String(UI_CONFIG.DEFAULT_PROXY_PORT_BY_PROTOCOL[next]));
    }
  };

  const openNewProxyModal = () => {
    setEditingProxyId(null);
    setExistingHasPassword(false);
    setReplacingPassword(true);
    setQuickPasteText('');
    setQuickPasteApplied(false);
    setName('');
    setProtocol('socks5');
    setHost('');
    setPortInput(String(UI_CONFIG.DEFAULT_PROXY_PORT));
    setPortTouched(false);
    setProtocolTouched(false);
    setQuickPasteInvalid(false);
    setShowPassword(false);
    setPortError(null);
    setUsername('');
    setPassword('');
    setUdpEnabled(true);
    setTls(false);
    setTlsSkipVerify(false);
    setShowAddProxy(true);
  };

  const openEditProxyModal = (proxy: ProxyNode) => {
    const hasPw = Boolean(proxy.auth?.hasPassword);
    setEditingProxyId(proxy.id);
    setExistingHasPassword(hasPw);
    setReplacingPassword(!hasPw);
    setQuickPasteText('');
    setQuickPasteApplied(false);
    setName(proxy.name);
    setProtocol(proxy.protocol);
    setHost(proxy.host);
    setPortInput(String(proxy.port));
    setPortTouched(true);
    setProtocolTouched(true);
    setQuickPasteInvalid(false);
    setShowPassword(false);
    setPortError(null);
    setUsername(proxy.auth?.username || '');
    setPassword('');
    setUdpEnabled(proxy.udpEnabled);
    setTls(proxy.tls);
    setTlsSkipVerify(Boolean(proxy.tlsSkipVerify));
    setShowAddProxy(true);
  };

  const handleCreateProxy = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !host.trim()) return;
    const hostField = resolveHostField(host.trim());
    const effectiveHost = hostField.host;
    const parsedPort =
      hostField.port !== null && !portTouched
        ? hostField.port
        : Number(portInput.trim());
    if (
      !Number.isInteger(parsedPort) ||
      parsedPort < 1 ||
      parsedPort > UI_CONFIG.MAX_PORT
    ) {
      setPortError(t('proxies.modal.add_proxy.port_error'));
      return;
    }
    setPortError(null);
    const cleanUser = username.trim();
    const shouldSendNewPassword = replacingPassword && password.length > 0;
    const authPayload =
      cleanUser || shouldSendNewPassword || existingHasPassword
        ? {
            username: cleanUser,
            ...(shouldSendNewPassword ? { password } : {}),
            hasPassword: shouldSendNewPassword ? true : existingHasPassword
          }
        : null;

    const effectiveTls = protocol === 'https' ? true : tls;
    const existing = editingProxyId
      ? proxies.find((p) => p.id === editingProxyId)
      : undefined;
    // Keep an explicit (imported) SNI that differs from the previous host; otherwise follow the host.
    const preservedSni =
      existing?.sni && existing.sni !== existing.host ? existing.sni : null;
    onAddProxy({
      id: editingProxyId || generateClientId('proxy'),
      name: name.trim(),
      protocol,
      host: effectiveHost,
      port: parsedPort,
      auth: authPayload,
      udpEnabled: protocol === 'socks5' ? udpEnabled : false,
      tls: effectiveTls,
      tlsSkipVerify: effectiveTls ? tlsSkipVerify : false,
      sni: effectiveTls ? (preservedSni ?? effectiveHost) : null,
      enabled: existing?.enabled ?? true,
      lastLatencyMs: null,
      exitIp: null
    });
    setName('');
    setPassword('');
    setEditingProxyId(null);
    setShowAddProxy(false);
  };

  const handleBatchUriSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!uriBatchText.trim()) return;
    onImportUris(
      normalizeProxyImportText(uriBatchText, UI_CONFIG.DEFAULT_LINK_PROXY_PROTOCOL)
    );
    setUriBatchText('');
    setShowImportUri(false);
  };

  const handleCreateChain = (e: React.FormEvent) => {
    e.preventDefault();
    if (!chainName.trim() || selectedHops.length === 0) return;
    onAddChain({
      id: generateClientId('chain'),
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
    if (!navigator.clipboard) {
      return;
    }
    // Confirm only once the clipboard write has actually succeeded.
    navigator.clipboard
      .writeText(uri)
      .then(() => onCopyUri(uri))
      .catch(() => {});
  };

  return (
    <div className="space-y-8">
      {/* Upstream Proxy Servers */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-tf-primary">
              {experienceMode === 'simple'
                ? t('proxies.simple.title')
                : t('proxies.section.servers.title')}
            </h2>
            {experienceMode === 'simple' && (
              <p className="text-xs text-tf-secondary">
                {t('proxies.simple.subtitle')}
              </p>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {experienceMode === 'expert' && (
              <button
                onClick={onTestAllProxies}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-tf-cyan hover:border-tf-cyan"
              >
                <Activity className="h-3.5 w-3.5" />
                {t('proxies.section.servers.test_all')}
              </button>
            )}
            <button
              type="button"
              disabled={detectingProxies}
              onClick={() => {
                void handleDetectExisting();
              }}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-tf-cyan hover:border-tf-cyan disabled:opacity-60"
            >
              <Radar className="h-3.5 w-3.5" />
              {detectingProxies
                ? t('proxies.simple.detecting')
                : t('proxies.simple.detect_button')}
            </button>
            {onPasteFromClipboard && (
              <button
                type="button"
                onClick={() => {
                  void onPasteFromClipboard();
                }}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-tf-green hover:border-tf-green"
              >
                <ClipboardPaste className="h-3.5 w-3.5" />
                {t('proxies.simple.paste_clipboard_button')}
              </button>
            )}
            <button
              type="button"
              onClick={() => setShowImportUri(true)}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-tf-primary hover:border-tf-accent"
            >
              <FileCode2 className="h-3.5 w-3.5 text-tf-accent" />
              {experienceMode === 'simple'
                ? t('proxies.simple.paste_link_button')
                : t('proxies.section.servers.import_uri')}
            </button>
            <button
              onClick={openNewProxyModal}
              className="tf-btn-accent flex items-center gap-1.5 px-3.5 py-1.5 text-xs"
            >
              <Plus className="h-3.5 w-3.5" />
              {experienceMode === 'simple'
                ? t('proxies.simple.add')
                : t('proxies.section.servers.add')}
            </button>
          </div>
        </div>

        <div className="rounded-tf-md border border-tf-cyan/30 bg-tf-cyan/10 p-4 text-xs">
          <div className="font-bold text-tf-primary">
            {t('proxies.external_explainer.title')}
          </div>
          <p className="mt-1 text-tf-secondary">
            {t('proxies.external_explainer.desc')}
          </p>
        </div>

        {detectFailed && (
          <div className="tf-card p-4 text-xs">
            <p role="alert" className="text-tf-orange">
              {t('proxies.simple.detect_failed')}
            </p>
          </div>
        )}

        {detectedCandidates !== null && (
          <div className="tf-card space-y-2.5 p-4 text-xs">
            {detectedCandidates.length === 0 ? (
              <p className="text-tf-secondary">
                {t('proxies.simple.detect_empty')}
              </p>
            ) : (
              detectedCandidates.map((cand) => (
                <div
                  key={`${cand.protocol}-${cand.host}-${cand.port}`}
                  className="tf-surface-alt flex flex-wrap items-center justify-between gap-3 p-3"
                >
                  <div>
                    <div className="font-bold text-tf-primary">{cand.name}</div>
                    <div className="font-mono text-[11px] text-tf-cyan">
                      {cand.protocol.toUpperCase()} - {cand.host}:{cand.port}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleImportDetectedCandidate(cand)}
                    className="tf-btn-accent px-3 py-1 text-xs"
                  >
                    {t('proxies.simple.detect_import')}
                  </button>
                </div>
              ))
            )}
          </div>
        )}

        {experienceMode === 'simple' && enabledProxies.length >= 2 && (
          <div className="tf-card flex flex-wrap items-center justify-between gap-4 p-4">
            <div className="flex items-start gap-3">
              <Link2 className="mt-0.5 h-5 w-5 shrink-0 text-tf-cyan" />
              <div>
                <div className="flex items-center gap-2 text-xs font-bold text-tf-primary">
                  <span>{t('proxies.simple.failover_title')}</span>
                  <span
                    className={`rounded-tf-sm px-2 py-0.5 text-[10px] font-bold ${
                      simpleFailoverEnabled
                        ? 'bg-tf-green/20 text-tf-green'
                        : 'bg-tf-surface-alt text-tf-secondary'
                    }`}
                  >
                    {simpleFailoverEnabled
                      ? t('proxies.simple.failover_enabled')
                      : t('proxies.simple.failover_disabled')}
                  </span>
                </div>
                <p className="mt-0.5 text-[11px] text-tf-secondary">
                  {t('proxies.simple.failover_desc')}
                </p>
              </div>
            </div>
            <input
              id={`${formId}-simple-failover`}
              type="checkbox"
              aria-label={t('proxies.simple.failover_title')}
              checked={simpleFailoverEnabled}
              onChange={handleToggleSimpleFailover}
              className="h-4 w-4 cursor-pointer accent-tf-accent"
            />
          </div>
        )}

        {proxies.length === 0 ? (
          <div className="tf-card p-6 text-center text-xs text-tf-secondary">
            {t('proxies.simple.empty')}
          </div>
        ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {proxies.map((proxy) => (
            <div
              key={proxy.id}
              className={`tf-card flex flex-col justify-between p-4 ${
                !proxy.enabled ? 'opacity-70' : ''
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Server className="h-4 w-4 text-tf-accent" />
                    <span className="font-bold text-tf-primary">
                      {proxy.name}
                    </span>
                    {primaryProxyId === proxy.id && (
                      <span className="rounded bg-tf-green/20 px-2 py-0.5 text-[10px] font-bold text-tf-green">
                        {t('proxies.simple.active_badge')}
                      </span>
                    )}
                    {!proxy.enabled && (
                      <span className="rounded bg-tf-surface-alt px-2 py-0.5 text-[10px] font-bold text-tf-secondary">
                        {t('proxies.simple.disabled_badge')}
                      </span>
                    )}
                  </div>
                  {experienceMode === 'expert' && (
                    <span className="rounded bg-tf-surface-alt px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-tf-accent">
                      {proxy.protocol}
                    </span>
                  )}
                </div>

                <div className="mt-2 font-mono text-xs text-tf-secondary">
                  {proxy.host}:{proxy.port}
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5 text-[10px]">
                  {experienceMode === 'expert' && (
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
                  )}
                  {proxy.tls && (
                    <span
                      className={`flex items-center gap-1 rounded px-2 py-0.5 font-semibold ${
                        proxy.tlsSkipVerify
                          ? 'bg-tf-orange/20 text-tf-orange'
                          : 'bg-tf-green/20 text-tf-green'
                      }`}
                    >
                      {proxy.tlsSkipVerify ? (
                        <AlertTriangle className="h-2.5 w-2.5" />
                      ) : (
                        <Lock className="h-2.5 w-2.5" />
                      )}
                      {proxy.tlsSkipVerify
                        ? t('proxies.card.badge.tls_insecure')
                        : t('proxies.card.badge.tls_enabled')}
                    </span>
                  )}
                  {proxy.auth?.hasPassword && (
                    <span className="flex items-center gap-1 rounded bg-tf-accent/20 px-2 py-0.5 font-semibold text-tf-accent">
                      <KeyRound className="h-2.5 w-2.5" />
                      {t('proxies.card.badge.password_set')}
                    </span>
                  )}
                  {proxy.lastLatencyMs !== null ? (
                    <span className="rounded bg-tf-green/20 px-2 py-0.5 font-mono font-bold text-tf-green">
                      {experienceMode === 'simple'
                        ? t('proxies.simple.status_ok')
                        : `${proxy.lastLatencyMs} ms`}
                    </span>
                  ) : unreachableProxyIds.includes(proxy.id) ? (
                    <span className="rounded bg-tf-red/20 px-2 py-0.5 font-semibold text-tf-red">
                      {experienceMode === 'simple'
                        ? t('proxies.simple.status_unreachable')
                        : t('proxies.card.badge.unreachable')}
                    </span>
                  ) : (
                    <span className="rounded bg-tf-surface-alt px-2 py-0.5 text-tf-secondary">
                      {experienceMode === 'simple'
                        ? t('proxies.simple.status_untested')
                        : t('proxies.card.badge.untested')}
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
                  className="flex items-center gap-1 text-xs font-semibold text-tf-accent hover:underline disabled:opacity-60"
                >
                  <Zap className="h-3.5 w-3.5" />
                  {testingId === proxy.id
                    ? t('proxies.card.action.testing')
                    : experienceMode === 'simple'
                      ? t('proxies.simple.test_connection')
                      : t('proxies.card.action.test')}
                </button>
                <div className="flex flex-wrap items-center gap-1.5">
                  {onSetPrimaryProxy &&
                    proxies.length >= 2 &&
                    primaryProxyId !== proxy.id && (
                      <button
                        type="button"
                        onClick={() => {
                          void onSetPrimaryProxy(proxy.id);
                        }}
                        className="flex items-center gap-1 rounded bg-tf-cyan/15 px-2 py-1 text-[11px] font-semibold text-tf-cyan transition hover:bg-tf-cyan/25"
                      >
                        <Star className="h-3 w-3" />
                        <span>{t('proxies.simple.set_primary')}</span>
                      </button>
                    )}
                  <button
                    type="button"
                    aria-pressed={proxy.enabled}
                    onClick={() =>
                      onAddProxy({ ...proxy, enabled: !proxy.enabled })
                    }
                    className={`flex items-center gap-1 rounded px-2 py-1 text-[11px] font-semibold transition ${
                      proxy.enabled
                        ? 'bg-tf-green/15 text-tf-green hover:bg-tf-green/25'
                        : 'bg-tf-surface-alt text-tf-secondary hover:text-tf-primary'
                    }`}
                    title={
                      proxy.enabled
                        ? t('proxies.simple.toggle_disable')
                        : t('proxies.simple.toggle_enable')
                    }
                  >
                    <Power className="h-3 w-3" />
                    <span>
                      {proxy.enabled
                        ? t('proxies.simple.toggle_disable')
                        : t('proxies.simple.toggle_enable')}
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => openEditProxyModal(proxy)}
                    className="flex items-center gap-1 rounded p-1.5 text-xs text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
                    title={t('proxies.card.action.edit')}
                    aria-label={t('proxies.card.action.edit')}
                  >
                    <Edit3 className="h-3.5 w-3.5" />
                  </button>
                  {experienceMode === 'expert' && (
                    <button
                      type="button"
                      onClick={() => handleCopyNodeUri(proxy)}
                      className="flex items-center gap-1 rounded p-1.5 text-xs text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
                      title={t('proxies.card.action.copy_uri')}
                      aria-label={t('proxies.card.action.copy_uri')}
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  )}
                  <ConfirmDeleteButton
                    armed={armedDeleteId === `proxy:${proxy.id}`}
                    title={t('proxies.card.action.delete')}
                    ariaLabel={t('proxies.card.action.delete')}
                    warningText={(() => {
                      const plan = planProxyRemoval(
                        proxy.id,
                        proxies,
                        chains,
                        rules
                      );
                      if (plan.affectedRules.length === 0) {
                        return undefined;
                      }
                      return plan.newPrimary
                        ? t('proxies.delete.warning_retarget', {
                            count: plan.affectedRules.length,
                            name: plan.newPrimary.name
                          })
                        : t('proxies.delete.warning_disable', {
                            count: plan.affectedRules.length
                          });
                    })()}
                    onArm={() => setArmedDeleteId(`proxy:${proxy.id}`)}
                    onConfirm={() => {
                      setArmedDeleteId(null);
                      onRemoveProxy(proxy.id);
                    }}
                    onCancel={() => setArmedDeleteId(null)}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
        )}
      </div>

      {/* Smart Proxy Chains & Failover Groups (Expert mode) */}
      {experienceMode === 'expert' && (
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
                      {t('proxies.section.chains.hops', {
                        count: chain.proxyIds.length
                      })}
                    </span>
                    <ConfirmDeleteButton
                      armed={armedDeleteId === `chain:${chain.id}`}
                      title={t('proxies.section.chains.delete')}
                      ariaLabel={t('proxies.section.chains.delete')}
                      onArm={() => setArmedDeleteId(`chain:${chain.id}`)}
                      onConfirm={() => {
                        setArmedDeleteId(null);
                        onRemoveChain(chain.id);
                      }}
                      onCancel={() => setArmedDeleteId(null)}
                    />
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
      )}

      {/* Batch Import URI Modal */}
      {showImportUri && (
        <ModalContainer
          onClose={() => setShowImportUri(false)}
          labelledBy={importTitleId}
          backdropClassName="bg-black/70 p-4"
        >
          <form
            onSubmit={handleBatchUriSubmit}
            className="tf-card w-full max-w-lg space-y-4 p-6"
          >
            <div>
              <h3 id={importTitleId} className="text-base font-bold text-tf-primary">
                {experienceMode === 'simple'
                  ? t('proxies.simple.import_title')
                  : t('proxies.modal.import_uri.title')}
              </h3>
              <p className="mt-1 text-xs text-tf-secondary">
                {experienceMode === 'simple'
                  ? t('proxies.simple.import_subtitle')
                  : t('proxies.modal.import_uri.subtitle')}
              </p>
            </div>
            <textarea name="proxy-uri-batch"
              rows={5}
              required
              aria-label={
                experienceMode === 'simple'
                  ? t('proxies.simple.import_title')
                  : t('proxies.modal.import_uri.title')
              }
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
        </ModalContainer>
      )}

      {/* Add Proxy Modal */}
      {showAddProxy && (
        <ModalContainer
          onClose={() => setShowAddProxy(false)}
          labelledBy={proxyTitleId}
          backdropClassName="bg-black/70 p-4"
        >
          <form
            onSubmit={handleCreateProxy}
            className="tf-card w-full max-w-md space-y-4 p-6"
          >
            <h3 id={proxyTitleId} className="text-base font-bold text-tf-primary">
              {editingProxyId
                ? t('proxies.modal.add_proxy.edit_title')
                : t('proxies.modal.add_proxy.title')}
            </h3>
            {!editingProxyId && (
              <div className="rounded-tf-md border border-tf-border bg-tf-surface-alt p-3">
                <label
                  htmlFor={`${formId}-quick-uri`}
                  className="block text-[11px] font-semibold text-tf-cyan"
                >
                  {t('proxies.modal.add_proxy.quick_paste_label')}
                </label>
                <input
                  id={`${formId}-quick-uri`}
                  type="text"
                  value={quickPasteText}
                  onChange={(e) => {
                    setQuickPasteText(e.target.value);
                    setQuickPasteInvalid(false);
                  }}
                  onPaste={(e) => {
                    const pasted = e.clipboardData.getData('text');
                    if (pasted && applyParsedLinkToForm(pasted)) {
                      e.preventDefault();
                      setQuickPasteText('');
                    }
                  }}
                  onBlur={(e) => commitQuickPaste(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      commitQuickPaste(e.currentTarget.value);
                    }
                  }}
                  placeholder={t('proxies.modal.add_proxy.quick_paste_placeholder')}
                  className="tf-input mt-1 w-full px-2.5 py-1.5 font-mono text-xs"
                />
                {quickPasteInvalid && (
                  <p role="alert" className="mt-1 text-[11px] font-semibold text-tf-red">
                    {t('proxies.modal.add_proxy.quick_paste_invalid')}
                  </p>
                )}
                {quickPasteApplied && (
                  <p className="mt-1 text-[11px] font-semibold text-tf-green">
                    {t('proxies.modal.add_proxy.quick_paste_applied')}
                  </p>
                )}
              </div>
            )}
            <div>
              <label htmlFor={`${formId}-f1`} className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_proxy.name_label')}
              </label>
              <input id={`${formId}-f1`}
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
              />
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label htmlFor={`${formId}-f2`} className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.protocol_label')}
                </label>
                <select id={`${formId}-f2`}
                  value={protocol}
                  onChange={(e) =>
                    handleProtocolChange(e.target.value as ProxyProtocol)
                  }
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
                <label htmlFor={`${formId}-f3`} className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.host_label')}
                </label>
                <input id={`${formId}-f3`}
                  type="text"
                  required
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  onBlur={(e) => commitHostField(e.target.value)}
                  placeholder={t('proxies.modal.add_proxy.host_placeholder')}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <label htmlFor={`${formId}-f4`} className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.port_label')}
                </label>
                <input id={`${formId}-f4`}
                  type="number"
                  min={1}
                  max={UI_CONFIG.MAX_PORT}
                  required
                  value={portInput}
                  onChange={(e) => {
                    setPortInput(e.target.value);
                    setPortTouched(true);
                    setPortError(null);
                  }}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
            </div>
            {portError && (
              <p role="alert" className="text-xs font-semibold text-tf-red">
                {portError}
              </p>
            )}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor={`${formId}-f5`} className="block text-xs text-tf-secondary">
                  {t('proxies.modal.add_proxy.username_label')}
                </label>
                <input id={`${formId}-f5`}
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
                />
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <label
                    htmlFor={`${formId}-password`}
                    className="block text-xs text-tf-secondary"
                  >
                    {t('proxies.modal.add_proxy.password_label')}
                  </label>
                  {existingHasPassword && (
                    <span className="flex items-center gap-1 text-[10px] font-bold text-tf-accent">
                      <KeyRound className="h-2.5 w-2.5" />
                      {t('proxies.card.badge.password_set')}
                    </span>
                  )}
                </div>
                <div className="relative mt-1">
                  <input
                    id={`${formId}-password`}
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    disabled={!replacingPassword}
                    placeholder={
                      existingHasPassword && !replacingPassword
                        ? t('proxies.modal.add_proxy.password_unchanged_placeholder')
                        : ''
                    }
                    onChange={(e) => setPassword(e.target.value)}
                    className="tf-input w-full py-1.5 pl-3 pr-9 text-sm disabled:opacity-60"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((prev) => !prev)}
                    aria-pressed={showPassword}
                    aria-label={
                      showPassword
                        ? t('proxies.modal.add_proxy.hide_password')
                        : t('proxies.modal.add_proxy.show_password')
                    }
                    title={
                      showPassword
                        ? t('proxies.modal.add_proxy.hide_password')
                        : t('proxies.modal.add_proxy.show_password')
                    }
                    className="absolute inset-y-0 right-0 flex items-center px-2.5 text-tf-secondary hover:text-tf-primary"
                  >
                    {showPassword ? (
                      <EyeOff className="h-3.5 w-3.5" />
                    ) : (
                      <Eye className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
                {existingHasPassword && (
                  <button
                    type="button"
                    onClick={() => {
                      setReplacingPassword((prev) => !prev);
                      setPassword('');
                    }}
                    className="mt-1 text-[11px] font-semibold text-tf-accent hover:underline"
                  >
                    {replacingPassword
                      ? t('proxies.modal.add_proxy.cancel_replace_password')
                      : t('proxies.modal.add_proxy.replace_password_action')}
                  </button>
                )}
              </div>
            </div>
            {experienceMode === 'expert' &&
              (protocol === 'http' || protocol === 'https') && (
              <p className="text-[11px] text-tf-secondary">
                {t('proxies.modal.add_proxy.sspi_hint')}
              </p>
            )}
            {experienceMode === 'simple' && (
              <button
                type="button"
                onClick={() => setShowProtocolOptions((prev) => !prev)}
                className="text-xs font-semibold text-tf-cyan hover:underline"
              >
                {showProtocolOptions
                  ? t('proxies.simple.hide_advanced_options')
                  : t('proxies.simple.show_advanced_options')}
              </button>
            )}
            {(experienceMode === 'expert' || showProtocolOptions) && (
              <div className="space-y-2 pt-1 text-xs text-tf-primary">
                <div className="flex items-center gap-6">
                  <label className="flex items-center gap-2">
                    <input name="proxy-udp-enabled"
                      type="checkbox"
                      checked={udpEnabled}
                      onChange={(e) => setUdpEnabled(e.target.checked)}
                    />
                    {t('proxies.modal.add_proxy.udp_label')}
                  </label>
                  <label className="flex items-center gap-2">
                    <input name="proxy-tls"
                      type="checkbox"
                      checked={tls || protocol === 'https'}
                      disabled={protocol === 'https'}
                      onChange={(e) => setTls(e.target.checked)}
                    />
                    {t('proxies.modal.add_proxy.tls_label')}
                  </label>
                </div>
                {(tls || protocol === 'https') && (
                  <label className="flex items-center gap-2 text-[11px] text-tf-orange">
                    <input name="proxy-tls-skip-verify"
                      type="checkbox"
                      checked={tlsSkipVerify}
                      onChange={(e) => setTlsSkipVerify(e.target.checked)}
                    />
                    {t('proxies.modal.add_proxy.tls_skip_verify_label')}
                  </label>
                )}
              </div>
            )}
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
        </ModalContainer>
      )}

      {/* Add Chain / Smart Group Modal */}
      {showAddChain && (
        <ModalContainer
          onClose={() => setShowAddChain(false)}
          labelledBy={chainTitleId}
          backdropClassName="bg-black/70 p-4"
        >
          <form
            onSubmit={handleCreateChain}
            className="tf-card w-full max-w-md space-y-4 p-6"
          >
            <h3 id={chainTitleId} className="text-base font-bold text-tf-primary">
              {t('proxies.modal.add_chain.title')}
            </h3>
            <div>
              <label htmlFor={`${formId}-f6`} className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_chain.name_label')}
              </label>
              <input id={`${formId}-f6`}
                type="text"
                required
                value={chainName}
                onChange={(e) => setChainName(e.target.value)}
                className="tf-input mt-1 w-full px-3 py-1.5 text-sm"
              />
            </div>
            <div>
              <label htmlFor={`${formId}-f7`} className="block text-xs text-tf-secondary">
                {t('proxies.modal.add_chain.strategy_label')}
              </label>
              <select id={`${formId}-f7`}
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
                      className="inline-flex items-center gap-1 rounded bg-tf-accent/20 px-2 py-0.5 font-mono text-tf-accent"
                    >
                      <span>
                        {i + 1}. {p?.name || id}
                      </span>
                      <button
                        type="button"
                        disabled={i === 0}
                        onClick={() =>
                          setSelectedHops((prev) => {
                            const next = [...prev];
                            [next[i - 1], next[i]] = [next[i], next[i - 1]];
                            return next;
                          })
                        }
                        aria-label={t('proxies.modal.add_chain.move_hop_up')}
                        title={t('proxies.modal.add_chain.move_hop_up')}
                        className="rounded p-0.5 hover:bg-tf-accent/20 disabled:opacity-30"
                      >
                        <ArrowUp className="h-3 w-3" />
                      </button>
                      <button
                        type="button"
                        disabled={i === selectedHops.length - 1}
                        onClick={() =>
                          setSelectedHops((prev) => {
                            const next = [...prev];
                            [next[i], next[i + 1]] = [next[i + 1], next[i]];
                            return next;
                          })
                        }
                        aria-label={t('proxies.modal.add_chain.move_hop_down')}
                        title={t('proxies.modal.add_chain.move_hop_down')}
                        className="rounded p-0.5 hover:bg-tf-accent/20 disabled:opacity-30"
                      >
                        <ArrowDown className="h-3 w-3" />
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setSelectedHops((prev) =>
                            prev.filter((_, idx) => idx !== i)
                          )
                        }
                        aria-label={t('proxies.modal.add_chain.remove_hop')}
                        title={t('proxies.modal.add_chain.remove_hop')}
                        className="rounded p-0.5 hover:text-tf-red"
                      >
                        <X className="h-3 w-3" />
                      </button>
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
        </ModalContainer>
      )}
    </div>
  );
};
