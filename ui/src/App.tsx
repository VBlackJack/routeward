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
  CheckCircle2,
  Home,
  Power,
  RefreshCw,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Wand2,
  X
} from 'lucide-react';
import {
  buildDefaultPacUrl,
  SYSTEM_CONSTANTS,
  UI_CONFIG
} from './config/constants';
import {
  generateClientId,
  HttpResponseError,
  routewardClient
} from './services/ipc';
import { useThemeForge } from './theme/ThemeForgeContext';
import {
  InterceptionMode,
  PortRange,
  ProfileSummary,
  ToastNotification,
  TransportProtocol
} from './types/routeward';
import {
  DashboardUseCaseId,
  DashboardView
} from './components/DashboardView';
import { ConnectionsView } from './components/ConnectionsView';
import { ProxiesView } from './components/ProxiesView';
import { RulesView } from './components/RulesView';
import { SettingsView } from './components/SettingsView';
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

export const App: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { activePalette, activeAccent } = useThemeForge();

  const [activeTab, setActiveTab] = useState<NavTabId>('home');
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
  const [pacEnabled, setPacEnabled] = useState(false);
  const [pacUrl, setPacUrl] = useState(buildDefaultPacUrl());
  const [autostartEnabled, setAutostartEnabled] = useState(false);
  const [namedProfiles, setNamedProfiles] = useState<ProfileSummary[]>([]);
  const [startingDaemon, setStartingDaemon] = useState(false);
  const [togglingEngine, setTogglingEngine] = useState(false);
  const togglingEngineRef = useRef(false);
  const [toasts, setToasts] = useState<ToastNotification[]>([]);
  const wizardAutoCheckedRef = useRef(false);

  const handleSetExperienceMode = (mode: ExperienceMode) => {
    setExperienceMode(mode);
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.EXPERIENCE_MODE, mode);
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

  const tabRefs = useRef<Partial<Record<NavTabId, HTMLButtonElement | null>>>({});

  useEffect(() => {
    const activeLocale: 'fr' | 'en' = i18n.language.startsWith('fr')
      ? 'fr'
      : 'en';
    document.documentElement.lang = activeLocale;
    void routewardClient.setDesktopLocale(activeLocale);
  }, [i18n.language]);

  useEffect(() => {
    if (!diagnostics.daemonConnected || wizardAutoCheckedRef.current) {
      return;
    }
    wizardAutoCheckedRef.current = true;
    const alreadyCompleted =
      window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED) ===
      'true';
    if (!alreadyCompleted) {
      setShowWizardModal(true);
    }
  }, [diagnostics.daemonConnected]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const pushToast = useCallback(
    (message: string, severity: ToastNotification['severity'] = 'success') => {
      const id = generateClientId('toast');
      setToasts((prev) => [...prev, { id, message, severity }]);
      // Error toasts stay until dismissed (WCAG 2.2.1); other toasts auto-dismiss.
      if (severity !== 'error') {
        window.setTimeout(() => {
          dismissToast(id);
        }, UI_CONFIG.TOAST_DURATION_MS);
      }
    },
    [dismissToast]
  );

  /** Builds the user-facing message of a failed call: translated errorKey, else detail, else fallback. */
  const describeError = useCallback(
    (err: unknown, fallbackKey: string): string => {
      if (err instanceof HttpResponseError) {
        if (err.errorKey && i18n.exists(err.errorKey)) {
          return t(err.errorKey);
        }
        if (err.message && !/^HTTP \d+$/.test(err.message)) {
          return err.message;
        }
      }
      return t(fallbackKey);
    },
    [i18n, t]
  );

  const pushErrorToast = useCallback(
    (err: unknown, fallbackKey: string = 'app.toast.error.generic') => {
      pushToast(describeError(err, fallbackKey), 'error');
    },
    [describeError, pushToast]
  );

  /** Runs a mutation: the success callback fires only after it resolves, otherwise an error toast shows. */
  const runMutation = useCallback(
    <T,>(
      operation: () => Promise<T>,
      onSuccess?: (result: T) => void,
      fallbackKey?: string
    ): void => {
      void operation()
        .then((result) => {
          onSuccess?.(result);
        })
        .catch((err: unknown) => {
          pushErrorToast(err, fallbackKey);
        });
    },
    [pushErrorToast]
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
          '1': 'home',
          '2': 'apps',
          '3': 'proxy',
          '4': 'activity',
          '5': 'settings'
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

  const handleSetLanguage = (nextLang: 'en' | 'fr') => {
    i18n.changeLanguage(nextLang);
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.LOCALE, nextLang);
  };

  const handleToggleLanguage = () => {
    handleSetLanguage(i18n.language.startsWith('fr') ? 'en' : 'fr');
  };

  const handleStartDaemon = async () => {
    if (startingDaemon) return;
    setStartingDaemon(true);
    try {
      const res = await routewardClient.startDaemon();
      if (res.connected) {
        pushToast(t('app.toast.daemon.started'), 'success');
      } else {
        pushToast(t('app.toast.daemon.start_failed'), 'warning');
      }
    } catch (err) {
      if (err instanceof HttpResponseError) {
        if (err.errorKey === 'uac_cancelled') {
          pushToast(t('app.toast.daemon.uac_cancelled'), 'warning');
          return;
        }
        const errorToastMap: Record<string, string> = {
          access_denied: 'app.toast.daemon.access_denied',
          insecure_profile: 'app.toast.daemon.insecure_profile',
          ipc_error: 'app.toast.daemon.ipc_error',
          not_elevated: 'app.toast.daemon.not_elevated',
          config_invalid: 'app.toast.daemon.config_invalid',
          daemon_exited: 'app.toast.daemon.daemon_exited',
        };
        const key = err.errorKey ? errorToastMap[err.errorKey] : undefined;
        if (key) {
          pushToast(t(key), 'error');
          return;
        }
      }
      pushToast(t('app.toast.daemon.start_failed'), 'error');
    } finally {
      setStartingDaemon(false);
    }
  };

  const handleToggleEngine = async (targetState: boolean) => {
    if (togglingEngineRef.current) return;
    togglingEngineRef.current = true;
    setTogglingEngine(true);
    try {
      await routewardClient.toggleEngine(targetState);
    } catch (err) {
      if (err instanceof HttpResponseError) {
        const engineErrorToastMap: Record<string, string> = {
          'errors.interceptor.driver_missing':
            'app.toast.engine.driver_missing',
          'errors.interceptor.open_failed': 'app.toast.engine.open_failed',
          'errors.interceptor.not_root': 'app.toast.engine.not_root',
          'errors.interceptor.nft_missing': 'app.toast.engine.nft_missing',
          'errors.interceptor.nft_failed': 'app.toast.engine.nft_failed'
        };
        const key = err.errorKey
          ? engineErrorToastMap[err.errorKey]
          : undefined;
        pushToast(t(key ?? 'app.toast.engine.start_failed'), 'error');
        return;
      }
      pushToast(t('app.toast.engine.start_failed'), 'error');
    } finally {
      togglingEngineRef.current = false;
      setTogglingEngine(false);
    }
  };

  useEffect(() => {
    void routewardClient.getPacStatus().then((res) => {
      setPacEnabled(res.enabled);
      setPacUrl(res.pacUrl);
    });
    void routewardClient.getAutostartStatus().then((res) => {
      setAutostartEnabled(res.enabled);
    });
    void routewardClient.getSystemProxyStatus().then((res) => {
      setSystemProxyEnabled(res.enabled);
    });
  }, []);

  useEffect(() => {
    if (!diagnostics.daemonConnected) {
      return;
    }
    void routewardClient.listNamedProfiles().then((list) => {
      setNamedProfiles(list);
    });
  }, [diagnostics.daemonConnected, profile.profileId, profile.name]);

  const handleToggleSystemProxy = async () => {
    const next = !systemProxyEnabled;
    try {
      const applied = await routewardClient.setSystemProxy(next);
      setSystemProxyEnabled(applied);
      pushToast(
        applied
          ? t('app.toast.system.proxy_enabled')
          : t('app.toast.system.proxy_disabled'),
        applied ? 'success' : 'info'
      );
    } catch (err) {
      pushErrorToast(err, 'app.toast.system.proxy_error');
    }
  };

  const handleTogglePac = async () => {
    const next = !pacEnabled;
    try {
      const res = await routewardClient.setSystemPac(next);
      setPacEnabled(res.enabled);
      setPacUrl(res.pacUrl);
      pushToast(
        res.enabled
          ? t('app.toast.system.pac_enabled')
          : t('app.toast.system.pac_disabled'),
        res.enabled ? 'success' : 'info'
      );
    } catch (err) {
      pushErrorToast(err, 'app.toast.system.pac_error');
    }
  };

  const handleToggleAutostart = async () => {
    const next = !autostartEnabled;
    try {
      const res = await routewardClient.setAutostart(next);
      setAutostartEnabled(res.enabled);
      pushToast(
        res.enabled
          ? t('app.toast.system.autostart_enabled')
          : t('app.toast.system.autostart_disabled'),
        res.enabled ? 'success' : 'info'
      );
    } catch (err) {
      pushErrorToast(err, 'app.toast.system.autostart_error');
    }
  };

  const handleSaveNamedProfile = async (name: string) => {
    try {
      const list = await routewardClient.saveNamedProfile(undefined, name);
      setNamedProfiles(list);
      pushToast(`${t('app.toast.profile.saved_named')}: ${name}`, 'success');
    } catch (err) {
      pushErrorToast(err, 'app.toast.profile.error');
    }
  };

  const handleSwitchNamedProfile = async (profileId: string) => {
    try {
      const switched = await routewardClient.switchNamedProfile(profileId);
      const list = await routewardClient.listNamedProfiles();
      setNamedProfiles(list);
      pushToast(
        `${t('app.toast.profile.switched')}: ${switched.name}`,
        'info'
      );
    } catch (err) {
      pushErrorToast(err, 'app.toast.profile.error');
    }
  };

  const handleDeleteNamedProfile = async (profileId: string) => {
    try {
      const list = await routewardClient.deleteNamedProfile(profileId);
      setNamedProfiles(list);
      pushToast(t('app.toast.profile.deleted'), 'warning');
    } catch (err) {
      pushErrorToast(err, 'app.toast.profile.error');
    }
  };

  const applyUseCase = async (useCase: DashboardUseCaseId) => {
    const enabledProxies = profile.proxies.filter((p) => p.enabled);
    const hasEnabledProxy = enabledProxies.length > 0;
    const enabledChains = hasEnabledProxy
      ? profile.chains.filter(
          (c) =>
            c.enabled &&
            c.proxyIds.some((pid) => enabledProxies.some((p) => p.id === pid))
        )
      : [];
    const primaryProxyId = enabledProxies[0]?.id;
    let skippedProxyRule = false;

    const applyPresetById = async (presetId: string) => {
      const preset = SYSTEM_CONSTANTS.rulePresets.find((p) => p.id === presetId);
      if (!preset) return;
      let actType = preset.suggestedActionType as
        | 'proxy'
        | 'chain'
        | 'direct'
        | 'block';
      let targetId: string | undefined;
      if (actType === 'proxy') {
        targetId = primaryProxyId;
      } else if (actType === 'chain') {
        if (enabledChains[0]?.id) {
          targetId = enabledChains[0].id;
        } else if (primaryProxyId) {
          actType = 'proxy';
          targetId = primaryProxyId;
        }
      }
      if ((actType === 'proxy' || actType === 'chain') && !targetId) {
        skippedProxyRule = true;
        return;
      }
      await routewardClient.upsertRule({
        id: `rule-uc-${preset.id}`,
        name: t(`${preset.i18nKey}.name`),
        enabled: true,
        priority: preset.priority,
        processPatterns: [...preset.processPatterns],
        domainPatterns: [...preset.domainPatterns],
        ipCidrs: [...preset.ipCidrs],
        portRanges: [...preset.portRanges] as PortRange[],
        protocol: preset.protocol as TransportProtocol,
        action: targetId ? { type: actType, targetId } : { type: actType }
      });
    };

    if (useCase === 'privacy') {
      await routewardClient.updateSecurityPolicy({
        killSwitchEnabled: true,
        strictDnsNoLocalFallback: true
      });
      await applyPresetById('preset-privacy-browsers');
      await applyPresetById('preset-block-os-telemetry');
      await applyPresetById('preset-rfc1918-direct');
    } else if (useCase === 'work') {
      await routewardClient.updateSecurityPolicy({
        strictDnsNoLocalFallback: true
      });
      await applyPresetById('preset-dev-toolchains');
      await applyPresetById('preset-rfc1918-direct');
    } else if (useCase === 'gaming') {
      const gamingApp = SYSTEM_CONSTANTS.visualAppCatalog.find(
        (c) => c.id === 'app-gaming'
      );
      if (gamingApp) {
        await routewardClient.upsertRule({
          id: `rule-visual-${gamingApp.id}`,
          name: t(`${gamingApp.i18nKey}.name`),
          enabled: true,
          priority: gamingApp.priority,
          processPatterns: [...gamingApp.processPatterns],
          domainPatterns: [],
          ipCidrs: [],
          portRanges: [],
          protocol: 'any',
          action: { type: 'direct' }
        });
      }
      await applyPresetById('preset-privacy-browsers');
    } else if (useCase === 'strict') {
      await routewardClient.updateSecurityPolicy({
        killSwitchEnabled: true,
        blockUdpOnTcpOnlyProxy: true,
        strictDnsNoLocalFallback: true,
        blockQuicUdp443: true,
        blockEncryptedDnsBypass: true
      });
      await applyPresetById('preset-block-os-telemetry');
    }

    pushToast(
      t(
        skippedProxyRule
          ? 'app.toast.usecase.applied_direct_no_proxy'
          : 'app.toast.usecase.applied'
      ),
      skippedProxyRule ? 'info' : 'success'
    );
  };

  const handleApplyUseCase = async (useCase: DashboardUseCaseId) => {
    try {
      await applyUseCase(useCase);
    } catch (err) {
      pushErrorToast(err);
    }
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

  const handleImportProfileFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        void routewardClient
          .importProfileJson(reader.result)
          .then(() => {
            pushToast(t('app.toast.profile.imported'));
          })
          .catch((err: unknown) => {
            pushErrorToast(err, 'app.toast.profile.import_error');
          });
      }
    };
    reader.onerror = () => {
      pushToast(t('app.toast.profile.import_error'), 'error');
    };
    reader.readAsText(file);
  };

  const securityPolicy = profile.securityPolicy || {
    killSwitchEnabled: true,
    blockUdpOnTcpOnlyProxy: true,
    strictDnsNoLocalFallback: true
  };

  const isEngineRunning = diagnostics.daemonConnected && diagnostics.running;

  const navItems: Array<{
    id: NavTabId;
    icon: React.FC<{ className?: string }>;
  }> = [
    { id: 'home', icon: Home },
    { id: 'apps', icon: Shield },
    { id: 'proxy', icon: Server },
    { id: 'activity', icon: Activity },
    { id: 'settings', icon: Settings }
  ];

  const statusPillClass = !diagnostics.daemonConnected
    ? 'bg-tf-red/15 text-tf-red border-tf-red/40'
    : isEngineRunning
      ? 'bg-tf-green/15 text-tf-green border-tf-green/40'
      : 'bg-tf-orange/15 text-tf-orange border-tf-orange/40';

  const statusPillText = !diagnostics.daemonConnected
    ? t('app.header.status.disconnected')
    : isEngineRunning
      ? t('app.header.status.protected')
      : t('app.header.status.paused');

  return (
    <div className="flex min-h-screen flex-col bg-tf-bg text-tf-primary">
      {/* Minimal Header (Logo + Status on Left; Mode, Quick Help, Protection CTA on Right) */}
      <header className="border-b border-tf-border bg-tf-surface px-6 py-3">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <RouteWardLogo size="md" />
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-base font-bold leading-tight text-tf-primary">
                  {t('app.header.brand.title')}
                </h1>
                <span
                  className={`flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-bold ${statusPillClass}`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      !diagnostics.daemonConnected
                        ? 'bg-tf-red'
                        : isEngineRunning
                          ? 'bg-tf-green'
                          : 'bg-tf-orange'
                    }`}
                  />
                  {statusPillText}
                </span>
              </div>
              {experienceMode === 'expert' && (
                <p className="text-xs text-tf-secondary">
                  {t('app.header.brand.subtitle')}
                </p>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Simple / Advanced Experience Mode Switcher */}
            <div
              className="flex items-center rounded-tf-md border border-tf-border bg-tf-bg p-0.5"
              title={t('app.experience_mode.tooltip')}
            >
              <button
                type="button"
                aria-pressed={experienceMode === 'simple'}
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
                aria-pressed={experienceMode === 'expert'}
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

            {/* Quick Setup Button */}
            <button
              type="button"
              onClick={() => setShowWizardModal(true)}
              className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-accent hover:border-tf-accent"
            >
              <Wand2 className="h-3.5 w-3.5" />
              <span>{t('app.help.wizard_button')}</span>
            </button>

            {/* Primary Enable / Pause Protection CTA */}
            <button
              type="button"
              disabled={!diagnostics.daemonConnected || togglingEngine}
              onClick={() => {
                void handleToggleEngine(!isEngineRunning);
              }}
              className={`flex items-center gap-2 rounded-tf-md px-3.5 py-1.5 text-xs font-bold transition disabled:cursor-not-allowed disabled:opacity-50 ${
                isEngineRunning
                  ? 'border border-tf-orange bg-tf-orange/15 text-tf-orange hover:bg-tf-orange/25'
                  : 'bg-tf-green text-tf-bg hover:opacity-90'
              }`}
            >
              <Power className="h-3.5 w-3.5" />
              {isEngineRunning
                ? t('app.header.engine.pause')
                : t('app.header.engine.start')}
            </button>
          </div>
        </div>
      </header>

      {/* Persistent Daemon Disconnected / Non-Elevated Warning Banner */}
      {!diagnostics.daemonConnected && (
        <div className="border-b border-tf-red/40 bg-tf-red/15 px-6 py-2.5">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-xs lg:flex-nowrap">
            <div className="flex items-center gap-2.5 lg:min-w-0 lg:flex-1">
              <AlertTriangle className="h-4 w-4 shrink-0 text-tf-red" />
              <div>
                <span className="font-bold text-tf-red">
                  {t('app.daemon_banner.disconnected_title')}
                </span>{' '}
                <span className="text-tf-primary">
                  - {t('app.daemon_banner.disconnected_desc')}
                </span>
              </div>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <span className="rounded bg-tf-red/20 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-tf-red">
                {t('app.daemon_banner.reconnecting_badge')}
              </span>
              {diagnostics.osName === 'WINDOWS' && (
                <button
                  type="button"
                  disabled={startingDaemon}
                  onClick={() => {
                    void handleStartDaemon();
                  }}
                  className="tf-btn-accent flex items-center gap-1.5 px-3 py-1 text-xs disabled:opacity-60"
                >
                  <Power className="h-3 w-3" />
                  {startingDaemon
                    ? t('app.daemon_banner.starting_button')
                    : t('app.daemon_banner.start_button')}
                </button>
              )}
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
                - {t('app.daemon_banner.not_elevated_desc')}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <nav className="border-b border-tf-border bg-tf-surface/60 px-6">
        <div
          role="tablist"
          aria-label={t('app.nav.tablist_label')}
          className="mx-auto flex max-w-7xl gap-1 overflow-x-auto"
        >
          {navItems.map(({ id, icon: Icon }, idx) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                ref={(el) => {
                  tabRefs.current[id] = el;
                }}
                type="button"
                role="tab"
                aria-selected={active}
                tabIndex={active ? 0 : -1}
                onClick={() => setActiveTab(id)}
                onKeyDown={(e) => {
                  let targetIdx: number | null = null;
                  if (e.key === 'ArrowRight') {
                    targetIdx = (idx + 1) % navItems.length;
                  } else if (e.key === 'ArrowLeft') {
                    targetIdx = (idx - 1 + navItems.length) % navItems.length;
                  } else if (e.key === 'Home') {
                    targetIdx = 0;
                  } else if (e.key === 'End') {
                    targetIdx = navItems.length - 1;
                  }
                  if (targetIdx !== null) {
                    e.preventDefault();
                    const nextId = navItems[targetIdx].id;
                    setActiveTab(nextId);
                    tabRefs.current[nextId]?.focus();
                  }
                }}
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
        {activeTab === 'home' && (
          <DashboardView
            telemetry={telemetry}
            diagnostics={diagnostics}
            dnsCount={fakeIps.length}
            securityPolicy={securityPolicy}
            experienceMode={experienceMode}
            proxies={profile.proxies}
            rules={profile.rules}
            onToggleEngine={() => {
              void handleToggleEngine(!isEngineRunning);
            }}
            onApplyUseCase={handleApplyUseCase}
            onTestPrimaryProxy={(proxyId) => {
              runMutation(
                () => routewardClient.testProxy(proxyId),
                () => pushToast(t('app.toast.proxy.tested'))
              );
            }}
            onNavigateProxy={() => setActiveTab('proxy')}
            onUpdateSecurityPolicy={(partial) => {
              runMutation(() => routewardClient.updateSecurityPolicy(partial));
            }}
            onOpenWizard={() => setShowWizardModal(true)}
            onNavigateRules={() => setActiveTab('apps')}
            onSwitchToExpert={() => handleSetExperienceMode('expert')}
          />
        )}

        {activeTab === 'apps' && (
          <RulesView
            rules={profile.rules}
            proxies={profile.proxies}
            chains={profile.chains}
            experienceMode={experienceMode}
            onEvaluateRule={(req) => routewardClient.evaluateRule(req)}
            onAddRule={(rule) => {
              const isUpdate = profile.rules.some((r) => r.id === rule.id);
              runMutation(
                () => routewardClient.upsertRule(rule),
                () =>
                  pushToast(
                    t(
                      isUpdate
                        ? 'app.toast.rule.updated'
                        : 'app.toast.rule.created'
                    ),
                    isUpdate ? 'info' : 'success'
                  )
              );
            }}
            onToggleRule={(id) => {
              runMutation(
                () => routewardClient.toggleRuleEnabled(id),
                () => pushToast(t('app.toast.rule.updated'), 'info')
              );
            }}
            onReorderRule={(id, dir) => {
              runMutation(() => routewardClient.reorderRulePriority(id, dir));
            }}
            onRemoveRule={(id) => {
              runMutation(
                () => routewardClient.removeRule(id),
                () => pushToast(t('app.toast.rule.deleted'), 'warning')
              );
            }}
            onImportFoxyProxy={async (jsonText, processPatterns) => {
              try {
                const res = await routewardClient.importFoxyProxyJson(
                  jsonText,
                  processPatterns
                );
                pushToast(
                  `${t('app.toast.foxyproxy.imported')} (${res.rules.length})`,
                  'success'
                );
                return res;
              } catch (err) {
                pushErrorToast(err, 'app.toast.foxyproxy.import_error');
                return null;
              }
            }}
            onListSystemApps={() => routewardClient.listSystemApplications()}
            onMissingProxy={() => {
              pushToast(t('app.toast.proxy.required_for_rule'), 'warning');
              setActiveTab('proxy');
            }}
          />
        )}

        {activeTab === 'proxy' && (
          <ProxiesView
            proxies={profile.proxies}
            chains={profile.chains}
            experienceMode={experienceMode}
            onTestProxy={async (id) => {
              try {
                await routewardClient.testProxy(id);
                pushToast(t('app.toast.proxy.tested'));
              } catch (err) {
                pushErrorToast(err);
              }
            }}
            onTestAllProxies={async () => {
              try {
                await routewardClient.testAllProxies();
                pushToast(t('app.toast.proxy.tested'));
              } catch (err) {
                pushErrorToast(err);
              }
            }}
            onAddProxy={(node) => {
              runMutation(
                () => routewardClient.upsertProxy(node),
                () => pushToast(t('app.toast.proxy.added'))
              );
            }}
            onImportUris={(text) => {
              runMutation(
                () => routewardClient.importProxyUris(text),
                (count) => {
                  if (count > 0) {
                    pushToast(
                      `${t('app.toast.proxy.imported_uris')} (${count})`
                    );
                  }
                }
              );
            }}
            onCopyUri={() => {
              pushToast(t('app.toast.proxy.copied_uri'), 'info');
            }}
            onRemoveProxy={(id) => {
              runMutation(() => routewardClient.removeProxy(id));
            }}
            onAddChain={(chain) => {
              runMutation(() => routewardClient.upsertChain(chain));
            }}
            onRemoveChain={(id) => {
              runMutation(() => routewardClient.removeChain(id));
            }}
          />
        )}

        {activeTab === 'activity' && (
          <ConnectionsView
            connections={connections}
            proxies={profile.proxies}
            experienceMode={experienceMode}
            onScanOsSockets={async () => {
              try {
                await routewardClient.scanRealOsSockets();
                pushToast(t('app.toast.connection.os_scanned'), 'info');
              } catch (err) {
                pushErrorToast(err);
              }
            }}
            onClearClosed={() => {
              runMutation(() => routewardClient.clearClosedConnections());
            }}
            onTerminateConnection={(connId) => {
              runMutation(
                () => routewardClient.terminateConnection(connId),
                () => pushToast(t('app.toast.connection.terminated'), 'warning')
              );
            }}
            onQuickCreateRule={(rule) => {
              runMutation(
                () => routewardClient.upsertRule(rule),
                () => pushToast(t('app.toast.rule.created'))
              );
            }}
            onMissingProxy={() => {
              pushToast(t('app.toast.proxy.required_for_rule'), 'warning');
              setActiveTab('proxy');
            }}
            onSwitchToExpert={() => handleSetExperienceMode('expert')}
            onExportActivity={(fmt) => {
              pushToast(
                `${t('app.toast.connection.exported')} (${fmt.toUpperCase()})`,
                'info'
              );
            }}
          />
        )}

        {activeTab === 'settings' && (
          <SettingsView
            diagnostics={diagnostics}
            securityPolicy={securityPolicy}
            experienceMode={experienceMode}
            systemProxyEnabled={systemProxyEnabled}
            fakeIps={fakeIps}
            logs={logs}
            activePaletteDisplayName={activePalette.displayName}
            activeAccent={activeAccent}
            language={i18n.language.startsWith('fr') ? 'fr' : 'en'}
            onUpdateSecurityPolicy={(partial) => {
              runMutation(() => routewardClient.updateSecurityPolicy(partial));
            }}
            onSetInterceptionMode={(mode: InterceptionMode) => {
              runMutation(() => routewardClient.setInterceptionMode(mode));
            }}
            onToggleSystemProxy={handleToggleSystemProxy}
            onOpenThemeForge={() => setShowThemeModal(true)}
            onToggleLanguage={handleSetLanguage}
            onOpenWizard={() => setShowWizardModal(true)}
            onOpenGlossary={() => setShowGlossaryModal(true)}
            onOpenLauncher={() => setShowLauncherModal(true)}
            onImportProfile={handleImportProfileFile}
            onExportProfile={handleExportProfile}
            onAllocateDns={(dom) => {
              runMutation(() => routewardClient.allocateFakeIp(dom));
            }}
            onFlushDns={() => {
              runMutation(
                () => routewardClient.flushFakeIps(),
                () => pushToast(t('app.toast.dns.flushed'), 'info')
              );
            }}
            onClearLogs={() => {
              runMutation(() => routewardClient.clearLogs());
            }}
            pacEnabled={pacEnabled}
            pacUrl={pacUrl}
            autostartEnabled={autostartEnabled}
            profiles={namedProfiles}
            onTogglePac={handleTogglePac}
            onCopyPacUrl={() => {
              pushToast(t('app.toast.system.pac_copied'), 'info');
            }}
            onToggleAutostart={handleToggleAutostart}
            onSaveNamedProfile={handleSaveNamedProfile}
            onSwitchNamedProfile={handleSwitchNamedProfile}
            onDeleteNamedProfile={handleDeleteNamedProfile}
          />
        )}
      </main>

      {/* Persistent Technical Status Bar (Expert Mode only) */}
      {experienceMode === 'expert' && (
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
      )}

      {/* Floating ThemeForge Toasts */}
      {toasts.length > 0 && (
        <div className="fixed bottom-12 right-6 z-50 flex flex-col gap-2">
          {toasts.map((toast) => (
            <div
              key={toast.id}
              role={toast.severity === 'error' ? 'alert' : 'status'}
              className={`tf-card flex items-center gap-2.5 border-l-4 px-4 py-2.5 text-xs font-medium text-tf-primary shadow-xl ${
                toast.severity === 'error'
                  ? 'border-l-tf-red'
                  : 'border-l-tf-accent'
              }`}
            >
              {toast.severity === 'error' ? (
                <AlertTriangle className="h-4 w-4 text-tf-red" />
              ) : (
                <CheckCircle2 className="h-4 w-4 text-tf-accent" />
              )}
              <span>{toast.message}</span>
              {toast.severity === 'error' && (
                <button
                  type="button"
                  onClick={() => dismissToast(toast.id)}
                  aria-label={t('app.toast.dismiss')}
                  className="ml-1 rounded-tf-sm p-0.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
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
          onImportUris={async (text) => {
            await routewardClient.importProxyUris(text);
            return routewardClient.getProfile().proxies;
          }}
          onAddRule={(rule) => routewardClient.upsertRule(rule)}
          onSelectMode={(mode) => handleSetExperienceMode(mode)}
          onError={(err) => pushErrorToast(err)}
          onComplete={(hasEnabledProxy) => {
            window.localStorage.setItem(
              UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED,
              'true'
            );
            pushToast(
              t(
                hasEnabledProxy === false
                  ? 'app.toast.wizard.completed_direct_no_proxy'
                  : 'app.toast.wizard.completed'
              ),
              hasEnabledProxy === false ? 'info' : 'success'
            );
          }}
          onClose={() => {
            window.localStorage.setItem(
              UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED,
              'true'
            );
            setShowWizardModal(false);
          }}
        />
      )}

      {showLauncherModal && (
        <ProcessLauncherModal
          relayEndpoint={diagnostics.relayTcpEndpoint}
          onLaunch={async (exe, args) => {
            try {
              await routewardClient.launchProcessWithProxy(exe, args);
              pushToast(`${t('app.toast.system.process_launched')}: ${exe}`);
            } catch (err) {
              pushToast(t('app.toast.system.process_launch_error'), 'error');
              throw err;
            }
          }}
          onClose={() => setShowLauncherModal(false)}
        />
      )}

      {showCommandPalette && (
        <CommandPaletteModal
          onClose={() => setShowCommandPalette(false)}
          onNavigate={(tab) => setActiveTab(tab)}
          onToggleEngine={() => {
            void handleToggleEngine(!isEngineRunning);
          }}
          onTestAllProxies={async () => {
            try {
              await routewardClient.testAllProxies();
              pushToast(t('app.toast.proxy.tested'));
            } catch (err) {
              pushErrorToast(err);
            }
          }}
          onFlushDns={() => {
            runMutation(
              () => routewardClient.flushFakeIps(),
              () => pushToast(t('app.toast.dns.flushed'), 'info')
            );
          }}
          onToggleKillSwitch={() => {
            runMutation(() =>
              routewardClient.updateSecurityPolicy({
                killSwitchEnabled: !securityPolicy.killSwitchEnabled
              })
            );
          }}
          onOpenThemeForge={() => setShowThemeModal(true)}
          onSwitchLanguage={handleToggleLanguage}
        />
      )}
    </div>
  );
};
