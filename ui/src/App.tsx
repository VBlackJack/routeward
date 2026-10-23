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

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  Command,
  Download,
  FileText,
  Globe,
  Languages,
  LayoutDashboard,
  Network,
  Palette,
  Power,
  RefreshCw,
  Rocket,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Upload,
  Wand2
} from 'lucide-react';
import { UI_CONFIG } from './config/constants';
import { generateClientId, routewardClient } from './services/ipc';
import { useThemeForge } from './theme/ThemeForgeContext';
import { InterceptionMode, ToastNotification } from './types/routeward';
import { DashboardView } from './components/DashboardView';
import { ConnectionsView } from './components/ConnectionsView';
import { ProxiesView } from './components/ProxiesView';
import { RulesView } from './components/RulesView';
import { DnsView } from './components/DnsView';
import { LogsView } from './components/LogsView';
import { ThemeForgeModal } from './components/ThemeForgeModal';
import {
  CommandPaletteModal,
  NavTabId
} from './components/CommandPaletteModal';
import { RouteWardLogo } from './components/RouteWardLogo';
import { ProcessLauncherModal } from './components/ProcessLauncherModal';
import {
  ExperienceMode,
  QuickSetupWizardModal
} from './components/QuickSetupWizardModal';
import { GlossaryModal } from './components/GlossaryModal';

const TOAST_DURATION_MS = 3200;

export const App: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { activePalette, activeAccent } = useThemeForge();

  const [activeTab, setActiveTab] = useState<NavTabId>('dashboard');
  const [experienceMode, setExperienceMode] = useState<ExperienceMode>(() => {
    const saved = window.localStorage.getItem(
      UI_CONFIG.STORAGE_KEYS.EXPERIENCE_MODE
    );
    return saved === 'expert' ? 'expert' : 'simple';
  });
  const [showThemeModal, setShowThemeModal] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [showLauncherModal, setShowLauncherModal] = useState(false);
  const [showWizardModal, setShowWizardModal] = useState(false);
  const [showGlossaryModal, setShowGlossaryModal] = useState(false);
  const [systemProxyEnabled, setSystemProxyEnabled] = useState(false);
  const [toasts, setToasts] = useState<ToastNotification[]>([]);

  const handleSetExperienceMode = (mode: ExperienceMode) => {
    setExperienceMode(mode);
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.EXPERIENCE_MODE, mode);
    if (mode === 'simple' && (activeTab === 'dns' || activeTab === 'logs')) {
      setActiveTab('dashboard');
    }
  };

  const [profile, setProfile] = useState(() => routewardClient.getProfile());
  const [diagnostics, setDiagnostics] = useState(() =>
    routewardClient.getDiagnostics()
  );
  const [telemetry, setTelemetry] = useState(() =>
    routewardClient.getTelemetry()
  );
  const [connections, setConnections] = useState(() =>
    routewardClient.listConnections()
  );
  const [fakeIps, setFakeIps] = useState(() => routewardClient.listFakeIps());
  const [logs, setLogs] = useState(() => routewardClient.listLogs());

  const importInputRef = useRef<HTMLInputElement | null>(null);

  const pushToast = useCallback(
    (message: string, severity: ToastNotification['severity'] = 'success') => {
      const id = generateClientId('toast');
      setToasts((prev) => [...prev, { id, message, severity }]);
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((item) => item.id !== id));
      }, TOAST_DURATION_MS);
    },
    []
  );

  const syncFromClient = useCallback(() => {
    setProfile(routewardClient.getProfile());
    setDiagnostics(routewardClient.getDiagnostics());
    setTelemetry(routewardClient.getTelemetry());
    setConnections(routewardClient.listConnections());
    setFakeIps(routewardClient.listFakeIps());
    setLogs(routewardClient.listLogs());
  }, []);

  useEffect(() => {
    const unsubscribe = routewardClient.subscribe(syncFromClient);
    const abortController = new AbortController();
    routewardClient.startRealtimeStream(abortController.signal);
    return () => {
      abortController.abort();
      unsubscribe();
    };
  }, [syncFromClient]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setShowCommandPalette((prev) => !prev);
      } else if (e.altKey) {
        const map: Record<string, NavTabId> = {
          '1': 'dashboard',
          '2': 'connections',
          '3': 'proxies',
          '4': 'rules',
          '5': 'dns',
          '6': 'logs'
        };
        if (map[e.key]) {
          e.preventDefault();
          setActiveTab(map[e.key]);
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleToggleLanguage = () => {
    const nextLang = i18n.language.startsWith('fr') ? 'en' : 'fr';
    i18n.changeLanguage(nextLang);
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, nextLang);
  };

  const handleExportProfile = () => {
    const json = routewardClient.exportProfileJson();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${profile.name.toLowerCase().replace(/\s+/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    pushToast(t('app.toast.profile.exported'), 'info');
  };

  const handleImportProfile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        void routewardClient.importProfileJson(reader.result).then(() => {
          pushToast(t('app.toast.profile.imported'));
        });
      }
    };
    reader.readAsText(file);
  };

  const securityPolicy = profile.securityPolicy || {
    killSwitchEnabled: true,
    blockUdpOnTcpOnlyProxy: true,
    strictDnsNoLocalFallback: true
  };

  const isEngineRunning = diagnostics.daemonConnected && diagnostics.running;

  const allNavItems: Array<{
    id: NavTabId;
    icon: React.FC<{ className?: string }>;
    expertOnly?: boolean;
  }> = [
    { id: 'dashboard', icon: LayoutDashboard },
    { id: 'connections', icon: Activity },
    { id: 'proxies', icon: Server },
    { id: 'rules', icon: Shield },
    { id: 'dns', icon: Globe, expertOnly: true },
    { id: 'logs', icon: FileText, expertOnly: true }
  ];

  const navItems = allNavItems.filter(
    (item) => experienceMode === 'expert' || !item.expertOnly
  );

  return (
    <div className="flex min-h-screen flex-col bg-tf-bg text-tf-primary">
      {/* Top Header */}
      <header className="border-b border-tf-border bg-tf-surface px-6 py-3">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <RouteWardLogo size="md" />
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold leading-tight text-tf-primary">
                  {t('app.header.brand.title')}
                </h1>
                <span className="rounded bg-tf-accent/15 px-1.5 py-0.5 font-mono text-[10px] font-bold text-tf-accent">
                  {t('app.titlebar.native_badge')}
                </span>
              </div>
              <p className="text-xs text-tf-secondary">
                {t('app.header.brand.subtitle')}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Simple / Expert Experience Mode Switcher */}
            <div
              className="flex items-center rounded-tf-md border border-tf-border bg-tf-bg p-0.5"
              title={t('app.experience_mode.tooltip')}
            >
              <button
                type="button"
                onClick={() => handleSetExperienceMode('simple')}
                className={`flex items-center gap-1 rounded-tf-sm px-2.5 py-1 text-xs font-bold transition ${
                  experienceMode === 'simple'
                    ? 'bg-tf-green text-tf-bg'
                    : 'text-tf-secondary hover:text-tf-primary'
                }`}
              >
                <Sparkles className="h-3 w-3" />
                <span>{t('app.experience_mode.simple')}</span>
              </button>
              <button
                type="button"
                onClick={() => handleSetExperienceMode('expert')}
                className={`flex items-center gap-1 rounded-tf-sm px-2.5 py-1 text-xs font-bold transition ${
                  experienceMode === 'expert'
                    ? 'bg-tf-cyan text-tf-bg'
                    : 'text-tf-secondary hover:text-tf-primary'
                }`}
              >
                <Terminal className="h-3 w-3" />
                <span>{t('app.experience_mode.expert')}</span>
              </button>
            </div>

            {/* Quick Setup Wizard Button */}
            <button
              onClick={() => setShowWizardModal(true)}
              className="tf-surface-alt flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-tf-accent hover:border-tf-accent"
              title={t('app.help.wizard_button')}
            >
              <Wand2 className="h-3.5 w-3.5" />
              <span className="hidden xl:inline">
                {t('app.help.wizard_button')}
              </span>
            </button>

            {/* Glossary & Help Guide Button */}
            <button
              onClick={() => setShowGlossaryModal(true)}
              className="tf-surface-alt flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-tf-secondary hover:border-tf-accent hover:text-tf-primary"
              title={t('app.help.glossary_button')}
            >
              <BookOpen className="h-3.5 w-3.5 text-tf-accent" />
              <span className="hidden xl:inline">
                {t('app.help.glossary_button')}
              </span>
            </button>

            {/* Process Launcher ("Run with RouteWard") */}
            <button
              onClick={() => setShowLauncherModal(true)}
              className="tf-surface-alt flex items-center gap-1.5 border-tf-cyan/50 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
            >
              <Rocket className="h-3.5 w-3.5" />
              <span className="hidden lg:inline">
                {t('app.launcher.button')}
              </span>
            </button>

            {/* 1-Click Windows System Proxy Toggle */}
            <button
              onClick={async () => {
                const next = !systemProxyEnabled;
                const applied = await routewardClient.setSystemProxy(next);
                setSystemProxyEnabled(applied);
                pushToast(
                  applied
                    ? t('app.toast.system.proxy_enabled')
                    : t('app.toast.system.proxy_disabled'),
                  applied ? 'success' : 'info'
                );
              }}
              title={t('app.system_proxy.tooltip')}
              className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                systemProxyEnabled
                  ? 'border border-tf-cyan bg-tf-cyan/20 text-tf-cyan'
                  : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
              }`}
            >
              <Network className="h-3.5 w-3.5" />
              <span className="hidden xl:inline">
                {systemProxyEnabled
                  ? t('app.system_proxy.active')
                  : t('app.system_proxy.inactive')}
              </span>
            </button>

            {/* Command Palette Button */}
            <button
              onClick={() => setShowCommandPalette(true)}
              className="tf-surface-alt flex items-center gap-2 px-3 py-1.5 text-xs text-tf-secondary hover:border-tf-accent hover:text-tf-primary"
            >
              <Command className="h-3.5 w-3.5 text-tf-accent" />
              <span className="hidden md:inline">
                {t('app.header.command_palette.button')}
              </span>
              <kbd className="rounded bg-tf-bg px-1.5 py-0.5 font-mono text-[10px] font-bold text-tf-accent">
                {t('app.header.command_palette.shortcut')}
              </kbd>
            </button>

            {/* Interception Mode Selector (Expert Mode) */}
            {experienceMode === 'expert' && (
              <select
                value={diagnostics.interceptionMode}
                onChange={(e) => {
                  void routewardClient.setInterceptionMode(
                    e.target.value as InterceptionMode
                  );
                }}
                className="tf-input px-2.5 py-1.5 text-xs font-medium"
              >
                <option value="hybrid">{t('app.header.mode.hybrid')}</option>
                <option value="driver">{t('app.header.mode.driver')}</option>
                <option value="relay">{t('app.header.mode.relay')}</option>
              </select>
            )}

            {/* ThemeForge Button */}
            <button
              onClick={() => setShowThemeModal(true)}
              className="tf-surface-alt flex items-center gap-2 px-3 py-1.5 text-xs font-semibold text-tf-primary hover:border-tf-accent"
            >
              <Palette className="h-3.5 w-3.5 text-tf-accent" />
              <span>{t('app.header.theme.button')}:</span>
              <span className="text-tf-accent">
                {activePalette.displayName}
                {activeAccent !== 'Default' ? ` (${activeAccent})` : ''}
              </span>
            </button>

            {/* Import / Export Profile */}
            <button
              onClick={() => importInputRef.current?.click()}
              className="tf-surface-alt flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-tf-secondary hover:text-tf-primary"
              title={t('app.header.profile.import')}
            >
              <Upload className="h-3.5 w-3.5" />
            </button>
            <input
              ref={importInputRef}
              type="file"
              accept=".json"
              className="hidden"
              onChange={handleImportProfile}
            />

            <button
              onClick={handleExportProfile}
              className="tf-surface-alt flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-tf-secondary hover:text-tf-primary"
              title={t('app.header.profile.export')}
            >
              <Download className="h-3.5 w-3.5" />
            </button>

            {/* Language Switcher */}
            <button
              onClick={handleToggleLanguage}
              className="tf-surface-alt flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-bold uppercase text-tf-primary hover:border-tf-accent"
              title={t('app.header.language.switch')}
            >
              <Languages className="h-3.5 w-3.5 text-tf-accent" />
              {i18n.language.slice(0, 2)}
            </button>

            {/* Start / Stop Engine */}
            <button
              disabled={!diagnostics.daemonConnected}
              onClick={() => {
                void routewardClient.toggleEngine(!isEngineRunning);
              }}
              className={`flex items-center gap-2 rounded-tf-md px-3.5 py-1.5 text-xs font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                isEngineRunning
                  ? 'border border-tf-green bg-tf-green/20 text-tf-green'
                  : 'border border-tf-red bg-tf-red/20 text-tf-red'
              }`}
            >
              <Power className="h-3.5 w-3.5" />
              {isEngineRunning
                ? t('app.header.engine.running')
                : t('app.header.engine.stopped')}
            </button>
          </div>
        </div>
      </header>

      {/* Persistent Daemon Disconnected / Non-Elevated Warning Banner */}
      {!diagnostics.daemonConnected && (
        <div className="border-b border-tf-red/40 bg-tf-red/15 px-6 py-2.5">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0 text-tf-red" />
              <div>
                <span className="font-bold text-tf-red">
                  {t('app.daemon_banner.disconnected_title')}
                </span>{' '}
                <span className="text-tf-primary">
                  — {t('app.daemon_banner.disconnected_desc')}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-tf-red/20 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-tf-red">
                {t('app.daemon_banner.reconnecting_badge')}
              </span>
              <button
                type="button"
                onClick={() => {
                  void routewardClient.fetchState();
                }}
                className="tf-surface-alt flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold text-tf-primary hover:border-tf-accent"
              >
                <RefreshCw className="h-3 w-3" />
                {t('app.daemon_banner.retry_button')}
              </button>
            </div>
          </div>
        </div>
      )}

      {diagnostics.daemonConnected && !diagnostics.elevatedPrivileges && (
        <div className="border-b border-tf-orange/40 bg-tf-orange/15 px-6 py-2.5">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-2.5 text-xs">
            <ShieldAlert className="h-4 w-4 shrink-0 text-tf-orange" />
            <div>
              <span className="font-bold text-tf-orange">
                {t('app.daemon_banner.not_elevated_title')}
              </span>{' '}
              <span className="text-tf-primary">
                — {t('app.daemon_banner.not_elevated_desc')}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <nav className="border-b border-tf-border bg-tf-surface/60 px-6">
        <div className="mx-auto flex max-w-7xl gap-1 overflow-x-auto">
          {navItems.map(({ id, icon: Icon }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-2 border-b-2 px-4 py-3 text-xs font-semibold transition ${
                  active
                    ? 'border-tf-accent text-tf-accent'
                    : 'border-transparent text-tf-secondary hover:text-tf-primary'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{t(`app.nav.${id}.tab`)}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Main Content */}
      <main className="mx-auto w-full max-w-7xl flex-1 p-6">
        {activeTab === 'dashboard' && (
          <DashboardView
            telemetry={telemetry}
            diagnostics={diagnostics}
            dnsCount={fakeIps.length}
            securityPolicy={securityPolicy}
            experienceMode={experienceMode}
            onUpdateSecurityPolicy={(partial) => {
              void routewardClient.updateSecurityPolicy(partial);
            }}
            onOpenWizard={() => setShowWizardModal(true)}
            onNavigateRules={() => setActiveTab('rules')}
            onSwitchToExpert={() => handleSetExperienceMode('expert')}
          />
        )}

        {activeTab === 'connections' && (
          <ConnectionsView
            connections={connections}
            proxies={profile.proxies}
            onScanOsSockets={async () => {
              await routewardClient.scanRealOsSockets();
              pushToast(t('app.toast.connection.os_scanned'), 'info');
            }}
            onClearClosed={() => {
              void routewardClient.clearClosedConnections();
            }}
            onTerminateConnection={(connId) => {
              void routewardClient.terminateConnection(connId).then(() => {
                pushToast(t('app.toast.connection.terminated'), 'warning');
              });
            }}
            onQuickCreateRule={(rule) => {
              void routewardClient.upsertRule(rule).then(() => {
                pushToast(t('app.toast.rule.created'));
              });
            }}
          />
        )}

        {activeTab === 'proxies' && (
          <ProxiesView
            proxies={profile.proxies}
            chains={profile.chains}
            onTestProxy={async (id) => {
              await routewardClient.testProxy(id);
              pushToast(t('app.toast.proxy.tested'));
            }}
            onTestAllProxies={async () => {
              await routewardClient.testAllProxies();
              pushToast(t('app.toast.proxy.tested'));
            }}
            onAddProxy={(node) => {
              void routewardClient.upsertProxy(node).then(() => {
                pushToast(t('app.toast.proxy.added'));
              });
            }}
            onImportUris={(text) => {
              void routewardClient.importProxyUris(text).then((count) => {
                if (count > 0) {
                  pushToast(`${t('app.toast.proxy.imported_uris')} (${count})`);
                }
              });
            }}
            onCopyUri={() => {
              pushToast(t('app.toast.proxy.copied_uri'), 'info');
            }}
            onRemoveProxy={(id) => {
              void routewardClient.removeProxy(id);
            }}
            onAddChain={(chain) => {
              void routewardClient.upsertChain(chain);
            }}
            onRemoveChain={(id) => {
              void routewardClient.removeChain(id);
            }}
          />
        )}

        {activeTab === 'rules' && (
          <RulesView
            rules={profile.rules}
            proxies={profile.proxies}
            chains={profile.chains}
            experienceMode={experienceMode}
            onEvaluateRule={(req) => routewardClient.evaluateRule(req)}
            onAddRule={(rule) => {
              void routewardClient.upsertRule(rule).then(() => {
                pushToast(t('app.toast.rule.created'));
              });
            }}
            onToggleRule={(id) => {
              void routewardClient.toggleRuleEnabled(id).then(() => {
                pushToast(t('app.toast.rule.updated'), 'info');
              });
            }}
            onReorderRule={(id, dir) => {
              void routewardClient.reorderRulePriority(id, dir);
            }}
            onRemoveRule={(id) => {
              void routewardClient.removeRule(id).then(() => {
                pushToast(t('app.toast.rule.deleted'), 'warning');
              });
            }}
          />
        )}

        {activeTab === 'dns' && (
          <DnsView
            entries={fakeIps}
            onAllocate={(dom) => {
              void routewardClient.allocateFakeIp(dom);
            }}
            onFlush={() => {
              void routewardClient.flushFakeIps().then(() => {
                pushToast(t('app.toast.dns.flushed'), 'info');
              });
            }}
          />
        )}

        {activeTab === 'logs' && (
          <LogsView
            logs={logs}
            onClear={() => {
              void routewardClient.clearLogs();
            }}
          />
        )}
      </main>

      {/* Persistent Status Bar */}
      <footer className="border-t border-tf-border bg-tf-surface px-6 py-2 text-[11px] text-tf-secondary">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <span className="flex items-center gap-1.5 font-mono">
              <span
                className={`h-2 w-2 rounded-full ${
                  isEngineRunning ? 'bg-tf-green' : 'bg-tf-red'
                }`}
              />
              {t('app.statusbar.relay.label')}:{' '}
              <strong className="text-tf-primary">
                {diagnostics.relayTcpEndpoint}
              </strong>
            </span>
            <span className="font-mono">
              {t('app.statusbar.dns.label')}:{' '}
              <strong className="text-tf-cyan">
                {diagnostics.fakeIpCidr} ({fakeIps.length})
              </strong>
            </span>
            <span
              className={`flex items-center gap-1 font-semibold ${
                securityPolicy.killSwitchEnabled
                  ? 'text-tf-green'
                  : 'text-tf-orange'
              }`}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              {securityPolicy.killSwitchEnabled
                ? t('app.statusbar.killswitch.active')
                : t('app.statusbar.killswitch.inactive')}
            </span>
          </div>

          <div className="flex items-center gap-4">
            <span>{t('app.statusbar.shortcut.hint')}</span>
            <span className="font-mono text-tf-accent">
              ThemeForge • {activePalette.displayName}
            </span>
          </div>
        </div>
      </footer>

      {/* Floating ThemeForge Toasts */}
      {toasts.length > 0 && (
        <div className="fixed bottom-12 right-6 z-50 flex flex-col gap-2">
          {toasts.map((toast) => (
            <div
              key={toast.id}
              className="tf-card flex items-center gap-2.5 border-l-4 border-l-tf-accent px-4 py-2.5 text-xs font-medium text-tf-primary shadow-xl"
            >
              <CheckCircle2 className="h-4 w-4 text-tf-accent" />
              <span>{toast.message}</span>
            </div>
          ))}
        </div>
      )}

      {showThemeModal && (
        <ThemeForgeModal onClose={() => setShowThemeModal(false)} />
      )}

      {showGlossaryModal && (
        <GlossaryModal onClose={() => setShowGlossaryModal(false)} />
      )}

      {showWizardModal && (
        <QuickSetupWizardModal
          proxies={profile.proxies}
          chains={profile.chains}
          currentMode={experienceMode}
          onImportUris={(text) => {
            void routewardClient.importProxyUris(text);
          }}
          onAddRule={(rule) => {
            void routewardClient.upsertRule(rule);
          }}
          onSelectMode={(mode) => handleSetExperienceMode(mode)}
          onComplete={() => {
            pushToast(t('app.toast.wizard.completed'));
          }}
          onClose={() => setShowWizardModal(false)}
        />
      )}

      {showLauncherModal && (
        <ProcessLauncherModal
          relayEndpoint={diagnostics.relayTcpEndpoint}
          onLaunch={async (exe, args) => {
            await routewardClient.launchProcessWithProxy(exe, args);
            pushToast(`${t('app.toast.system.process_launched')}: ${exe}`);
          }}
          onClose={() => setShowLauncherModal(false)}
        />
      )}

      {showCommandPalette && (
        <CommandPaletteModal
          onClose={() => setShowCommandPalette(false)}
          onNavigate={(tab) => setActiveTab(tab)}
          onToggleEngine={() => {
            void routewardClient.toggleEngine(!isEngineRunning);
          }}
          onTestAllProxies={async () => {
            await routewardClient.testAllProxies();
            pushToast(t('app.toast.proxy.tested'));
          }}
          onFlushDns={() => {
            void routewardClient.flushFakeIps().then(() => {
              pushToast(t('app.toast.dns.flushed'), 'info');
            });
          }}
          onToggleKillSwitch={() => {
            void routewardClient.updateSecurityPolicy({
              killSwitchEnabled: !securityPolicy.killSwitchEnabled
            });
          }}
          onOpenThemeForge={() => setShowThemeModal(true)}
          onSwitchLanguage={handleToggleLanguage}
        />
      )}
    </div>
  );
};
