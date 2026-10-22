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
import { proxifierClient } from './services/ipc';
import { useThemeForge } from './theme/ThemeForgeContext';
import { InterceptionMode, ToastNotification } from './types/proxifier';
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
import { ProxifierLogo } from './components/ProxifierLogo';
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

  const [profile, setProfile] = useState(() => proxifierClient.getProfile());
  const [diagnostics, setDiagnostics] = useState(() =>
    proxifierClient.getDiagnostics()
  );
  const [telemetry, setTelemetry] = useState(() =>
    proxifierClient.getTelemetry()
  );
  const [connections, setConnections] = useState(() =>
    proxifierClient.listConnections()
  );
  const [fakeIps, setFakeIps] = useState(() => proxifierClient.listFakeIps());
  const [logs, setLogs] = useState(() => proxifierClient.listLogs());

  const importInputRef = useRef<HTMLInputElement | null>(null);

  const pushToast = useCallback(
    (message: string, severity: ToastNotification['severity'] = 'success') => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      setToasts((prev) => [...prev, { id, message, severity }]);
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((item) => item.id !== id));
      }, TOAST_DURATION_MS);
    },
    []
  );

  const refreshAll = useCallback(() => {
    setProfile(proxifierClient.getProfile());
    setDiagnostics(proxifierClient.getDiagnostics());
    setTelemetry(proxifierClient.getTelemetry());
    setConnections(proxifierClient.listConnections());
    setFakeIps(proxifierClient.listFakeIps());
    setLogs(proxifierClient.listLogs());
  }, []);

  useEffect(() => {
    void proxifierClient.scanRealOsSockets().then((updated) => {
      setConnections(updated);
      setLogs(proxifierClient.listLogs());
    });
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setTelemetry(proxifierClient.getTelemetry());
      setConnections(proxifierClient.listConnections());
      setLogs(proxifierClient.listLogs());
    }, UI_CONFIG.TELEMETRY_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, []);

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
    const json = proxifierClient.exportProfileJson();
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
        proxifierClient.importProfileJson(reader.result);
        refreshAll();
        pushToast(t('app.toast.profile.imported'));
      }
    };
    reader.readAsText(file);
  };

  const securityPolicy = profile.securityPolicy || {
    killSwitchEnabled: true,
    blockUdpOnTcpOnlyProxy: true,
    strictDnsNoLocalFallback: true
  };

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
            <ProxifierLogo size="md" />
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

            {/* Process Launcher ("Run with Proxifier") */}
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
                await proxifierClient.setSystemProxy(next);
                setSystemProxyEnabled(next);
                refreshAll();
                pushToast(
                  next
                    ? t('app.toast.system.proxy_enabled')
                    : t('app.toast.system.proxy_disabled'),
                  next ? 'success' : 'info'
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
                  proxifierClient.setInterceptionMode(
                    e.target.value as InterceptionMode
                  );
                  refreshAll();
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
              onClick={() => {
                proxifierClient.toggleEngine(!diagnostics.running);
                refreshAll();
              }}
              className={`flex items-center gap-2 rounded-tf-md px-3.5 py-1.5 text-xs font-bold transition ${
                diagnostics.running
                  ? 'border border-tf-green bg-tf-green/20 text-tf-green'
                  : 'border border-tf-red bg-tf-red/20 text-tf-red'
              }`}
            >
              <Power className="h-3.5 w-3.5" />
              {diagnostics.running
                ? t('app.header.engine.running')
                : t('app.header.engine.stopped')}
            </button>
          </div>
        </div>
      </header>

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
              proxifierClient.updateSecurityPolicy(partial);
              refreshAll();
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
            onSimulate={(req) => {
              proxifierClient.simulateConnection(req);
              refreshAll();
            }}
            onScanOsSockets={async () => {
              await proxifierClient.scanRealOsSockets();
              refreshAll();
              pushToast(t('app.toast.connection.os_scanned'), 'info');
            }}
            onClearClosed={() => {
              proxifierClient.clearClosedConnections();
              refreshAll();
            }}
            onTerminateConnection={(connId) => {
              proxifierClient.terminateConnection(connId);
              refreshAll();
              pushToast(t('app.toast.connection.terminated'), 'warning');
            }}
            onQuickCreateRule={(rule) => {
              proxifierClient.upsertRule(rule);
              refreshAll();
              pushToast(t('app.toast.rule.created'));
            }}
          />
        )}

        {activeTab === 'proxies' && (
          <ProxiesView
            proxies={profile.proxies}
            chains={profile.chains}
            onTestProxy={async (id) => {
              await proxifierClient.testProxy(id);
              refreshAll();
              pushToast(t('app.toast.proxy.tested'));
            }}
            onTestAllProxies={async () => {
              await proxifierClient.testAllProxies();
              refreshAll();
              pushToast(t('app.toast.proxy.tested'));
            }}
            onAddProxy={(node) => {
              proxifierClient.upsertProxy(node);
              refreshAll();
              pushToast(t('app.toast.proxy.added'));
            }}
            onImportUris={(text) => {
              const count = proxifierClient.importProxyUris(text);
              refreshAll();
              if (count > 0) {
                pushToast(`${t('app.toast.proxy.imported_uris')} (${count})`);
              }
            }}
            onCopyUri={() => {
              pushToast(t('app.toast.proxy.copied_uri'), 'info');
            }}
            onRemoveProxy={(id) => {
              proxifierClient.removeProxy(id);
              refreshAll();
            }}
            onAddChain={(chain) => {
              proxifierClient.upsertChain(chain);
              refreshAll();
            }}
            onRemoveChain={(id) => {
              proxifierClient.removeChain(id);
              refreshAll();
            }}
          />
        )}

        {activeTab === 'rules' && (
          <RulesView
            rules={profile.rules}
            proxies={profile.proxies}
            chains={profile.chains}
            experienceMode={experienceMode}
            onEvaluateRule={(req) => proxifierClient.evaluateRule(req)}
            onAddRule={(rule) => {
              proxifierClient.upsertRule(rule);
              refreshAll();
              pushToast(t('app.toast.rule.created'));
            }}
            onToggleRule={(id) => {
              proxifierClient.toggleRuleEnabled(id);
              refreshAll();
              pushToast(t('app.toast.rule.updated'), 'info');
            }}
            onReorderRule={(id, dir) => {
              proxifierClient.reorderRulePriority(id, dir);
              refreshAll();
            }}
            onRemoveRule={(id) => {
              proxifierClient.removeRule(id);
              refreshAll();
              pushToast(t('app.toast.rule.deleted'), 'warning');
            }}
          />
        )}

        {activeTab === 'dns' && (
          <DnsView
            entries={fakeIps}
            onAllocate={(dom) => {
              proxifierClient.allocateFakeIp(dom);
              refreshAll();
            }}
            onFlush={() => {
              proxifierClient.flushFakeIps();
              refreshAll();
              pushToast(t('app.toast.dns.flushed'), 'info');
            }}
          />
        )}

        {activeTab === 'logs' && (
          <LogsView
            logs={logs}
            onClear={() => {
              proxifierClient.clearLogs();
              refreshAll();
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
                  diagnostics.running ? 'bg-tf-green' : 'bg-tf-red'
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
            proxifierClient.importProxyUris(text);
            refreshAll();
          }}
          onAddRule={(rule) => {
            proxifierClient.upsertRule(rule);
            refreshAll();
          }}
          onSelectMode={(mode) => handleSetExperienceMode(mode)}
          onComplete={() => {
            refreshAll();
            pushToast(t('app.toast.wizard.completed'));
          }}
          onClose={() => setShowWizardModal(false)}
        />
      )}

      {showLauncherModal && (
        <ProcessLauncherModal
          relayEndpoint={diagnostics.relayTcpEndpoint}
          onLaunch={async (exe, args) => {
            await proxifierClient.launchProcessWithProxy(exe, args);
            refreshAll();
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
            proxifierClient.toggleEngine(!diagnostics.running);
            refreshAll();
          }}
          onTestAllProxies={async () => {
            await proxifierClient.testAllProxies();
            refreshAll();
            pushToast(t('app.toast.proxy.tested'));
          }}
          onSimulateTraffic={() => {
            proxifierClient.simulateConnection(
              UI_CONFIG.SIMULATION_PRESETS[0]
            );
            refreshAll();
          }}
          onFlushDns={() => {
            proxifierClient.flushFakeIps();
            refreshAll();
            pushToast(t('app.toast.dns.flushed'), 'info');
          }}
          onToggleKillSwitch={() => {
            proxifierClient.updateSecurityPolicy({
              killSwitchEnabled: !securityPolicy.killSwitchEnabled
            });
            refreshAll();
          }}
          onOpenThemeForge={() => setShowThemeModal(true)}
          onSwitchLanguage={handleToggleLanguage}
        />
      )}
    </div>
  );
};
