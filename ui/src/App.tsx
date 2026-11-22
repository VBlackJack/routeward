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
  DEFAULT_PROFILE_DATA,
  UI_CONFIG
} from './config/constants';
import {
  generateClientId,
  HttpResponseError,
  routewardClient
} from './services/ipc';
import { useThemeForge } from './theme/ThemeForgeContext';
import {
  Finding,
  FixAction,
  InterceptionMode,
  ProfileSummary,
  ProxyChain,
  QueryLogsRequest,
  RoutingRule,
  ToastNotification
} from './types/routeward';
import {
  applyProxyRemovalToRule,
  getFriendlyAppName,
  isSimpleCreatedRuleId,
  normalizeProxyImportText,
  planProxyRemoval,
  slugifyRuleKey
} from './services/friendly';
import {
  computeProtectionHealth,
  formatPauseEnd,
  PROTECTION_HEALTH_TEXTS,
  resolveProxyReachability
} from './services/protectionHealth';
import {
  diffSecurityChanges,
  isUseCaseApplied,
  planShieldToggle,
  planUseCase,
  ShieldMix,
  SHIELD_SETTING_LABEL_KEYS
} from './services/protectionPresets';
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
import { TroubleshootModal } from './components/TroubleshootModal';
import { ConfirmApplyModal } from './components/ConfirmApplyModal';
import { ActivitySubtab, ActivitySubtabs } from './components/ActivitySubtabs';
import { AnalyzerPanel } from './components/AnalyzerPanel';
import { BlockedView } from './components/BlockedView';
import { DiagnosticExportModal } from './components/DiagnosticExportModal';
import { useUnblockFlow } from './components/useUnblockFlow';
import { LogsJump } from './services/logQuery';
import { useBlockedSummary } from './services/useBlockedSummary';

interface PendingConfirm {
  title: string;
  intro: string;
  changes: string[];
  onConfirm: () => void;
}

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
  const [showTroubleshootModal, setShowTroubleshootModal] = useState(false);
  const [outageDismissedForKey, setOutageDismissedForKey] = useState<string | null>(
    null
  );
  const [proxyOutageDetected, setProxyOutageDetected] = useState(false);
  const [systemProxyEnabled, setSystemProxyEnabled] = useState(false);
  const [pacEnabled, setPacEnabled] = useState(false);
  const [pacUrl, setPacUrl] = useState(buildDefaultPacUrl());
  const [autostartEnabled, setAutostartEnabled] = useState(false);
  const [namedProfiles, setNamedProfiles] = useState<ProfileSummary[]>([]);
  const [currentNetworkName, setCurrentNetworkName] = useState<string | null>(
    null
  );
  const [networkProfileRules, setNetworkProfileRules] = useState<
    Record<string, string>
  >(() => {
    try {
      const raw = window.localStorage.getItem(
        UI_CONFIG.STORAGE_KEYS.NETWORK_PROFILE_RULES
      );
      return raw ? (JSON.parse(raw) as Record<string, string>) : {};
    } catch {
      return {};
    }
  });
  const lastAutoSwitchedNetworkRef = useRef<string | null>(null);
  const [startingDaemon, setStartingDaemon] = useState(false);
  const [togglingEngine, setTogglingEngine] = useState(false);
  const togglingEngineRef = useRef(false);
  const [wizardCompleted, setWizardCompleted] = useState(
    () =>
      window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED) ===
      'true'
  );
  const [showServiceNotice, setShowServiceNotice] = useState(false);
  const [verifyRequestId, setVerifyRequestId] = useState(0);
  const [pendingConfirm, setPendingConfirm] = useState<PendingConfirm | null>(
    null
  );
  /** The user's own anti-leak mix, kept while the all-in-one shield is on. */
  const [rememberedShieldMix, setRememberedShieldMix] =
    useState<ShieldMix | null>(null);
  const prevPausedUntilRef = useRef<number | null>(null);
  const [draggingFile, setDraggingFile] = useState(false);
  const dragDepthRef = useRef(0);
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
    (
      message: string,
      severity: ToastNotification['severity'] = 'success',
      action?: { label: string; onAction: () => void }
    ) => {
      const id = generateClientId('toast');
      setToasts((prev) => [
        ...prev,
        {
          id,
          message,
          severity,
          actionLabel: action?.label,
          onAction: action?.onAction
        }
      ]);
      // Error toasts stay until dismissed (WCAG 2.2.1); other toasts auto-dismiss.
      if (severity !== 'error') {
        const duration = action
          ? UI_CONFIG.TOAST_UNDO_DURATION_MS
          : UI_CONFIG.TOAST_DURATION_MS;
        window.setTimeout(() => {
          dismissToast(id);
        }, duration);
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
      }
      // Technical detail stays in the console; the person only sees a plain sentence.
      console.warn('RouteWard request failed', err);
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

  const markServiceNoticeShown = () => {
    try {
      window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.SERVICE_NOTICE_SHOWN, 'true');
    } catch {
      // Storage can be unavailable; the notice then simply shows again next time.
    }
  };

  const handleStartDaemon = async (): Promise<boolean> => {
    if (startingDaemon) return false;
    setStartingDaemon(true);
    try {
      const res = await routewardClient.startDaemon();
      if (res.connected) {
        pushToast(t('app.toast.daemon.started'), 'success');
        if (res.fallbackReasonKey) {
          // The service could not be set up: say so, protection will not survive a restart.
          pushToast(t(res.fallbackReasonKey), 'warning');
        }
        let noticeSeen = false;
        try {
          noticeSeen =
            window.localStorage.getItem(
              UI_CONFIG.STORAGE_KEYS.SERVICE_NOTICE_SHOWN
            ) === 'true';
        } catch {
          noticeSeen = false;
        }
        if (!noticeSeen) {
          // One-time explanation that protection now lives in the background.
          setShowServiceNotice(true);
          markServiceNoticeShown();
        }
        return true;
      }
      pushToast(t('app.toast.daemon.start_failed'), 'warning');
      return false;
    } catch (err) {
      if (err instanceof HttpResponseError) {
        if (err.errorKey === 'uac_cancelled') {
          pushToast(t('app.toast.daemon.uac_cancelled'), 'warning');
          return false;
        }
        const errorToastMap: Record<string, string> = {
          access_denied: 'app.toast.daemon.access_denied',
          insecure_profile: 'app.toast.daemon.insecure_profile',
          ipc_error: 'app.toast.daemon.ipc_error',
          not_elevated: 'app.toast.daemon.not_elevated',
          config_invalid: 'app.toast.daemon.config_invalid',
          daemon_exited: 'app.toast.daemon.daemon_exited'
        };
        const key = err.errorKey ? errorToastMap[err.errorKey] : undefined;
        if (key) {
          pushToast(t(key), 'error');
          return false;
        }
      }
      pushErrorToast(err, 'app.toast.daemon.start_failed');
      return false;
    } finally {
      setStartingDaemon(false);
    }
  };

  const handleStartAndEnableProtection = async () => {
    if (startingDaemon || togglingEngineRef.current) return;
    const connected = await handleStartDaemon();
    if (connected && !routewardClient.getDiagnostics().running) {
      await handleToggleEngine(true);
    }
  };

  /**
   * Start button of the home hero and of the service banner. On the very first run only the
   * service starts and the setup assistant opens (it decides what to protect); afterwards the
   * service starts and protection is switched on, like the tray does.
   */
  const handleStartFromHome = async () => {
    if (startingDaemon || togglingEngineRef.current) return;
    if (!wizardCompleted) {
      const connected = await handleStartDaemon();
      if (connected) {
        setShowWizardModal(true);
      }
      return;
    }
    await handleStartAndEnableProtection();
  };

  const handleToggleEngine = useCallback(
    async (targetState: boolean): Promise<boolean> => {
      if (togglingEngineRef.current) return false;
      togglingEngineRef.current = true;
      setTogglingEngine(true);
      try {
        const diag = await routewardClient.toggleEngine(targetState);
        if (targetState && diag && diag.running === false) {
          pushToast(t('app.toast.engine.start_failed'), 'error');
          return false;
        }
        return true;
      } catch (err) {
        pushErrorToast(err, 'app.toast.engine.start_failed');
        return false;
      } finally {
        togglingEngineRef.current = false;
        setTogglingEngine(false);
      }
    },
    [pushErrorToast, pushToast, t]
  );

  /** Pauses protection in the daemon: it resumes by itself, even if this window is closed. */
  const handleTemporaryPause = async (minutes: number) => {
    if (togglingEngineRef.current) return;
    togglingEngineRef.current = true;
    setTogglingEngine(true);
    try {
      const diag = await routewardClient.pauseEngine(
        minutes * UI_CONFIG.SECONDS_PER_MINUTE
      );
      pushToast(
        diag && diag.pausedUntilEpochMs !== null
          ? t('app.toast.engine.paused_until', {
              time: formatPauseEnd(diag.pausedUntilEpochMs, i18n.language)
            })
          : t('app.toast.engine.paused_temporarily', { minutes }),
        'info'
      );
    } catch (err) {
      pushErrorToast(err, 'app.toast.engine.start_failed');
    } finally {
      togglingEngineRef.current = false;
      setTogglingEngine(false);
    }
  };

  // The daemon ends a pause by itself: say so when the deadline passes while the window is open.
  useEffect(() => {
    const previous = prevPausedUntilRef.current;
    prevPausedUntilRef.current = diagnostics.pausedUntilEpochMs;
    if (
      previous !== null &&
      diagnostics.pausedUntilEpochMs === null &&
      diagnostics.running &&
      Date.now() >= previous - UI_CONFIG.PAUSE_RESUME_TOAST_TOLERANCE_MS
    ) {
      pushToast(t('app.toast.engine.resumed_automatically'), 'success');
    }
  }, [diagnostics.pausedUntilEpochMs, diagnostics.running, pushToast, t]);

  useEffect(() => {
    let cancelled = false;
    void routewardClient.getPacStatus().then((res) => {
      if (cancelled) return;
      setPacEnabled(res.enabled);
      setPacUrl(res.pacUrl);
    });
    void routewardClient.getAutostartStatus().then((res) => {
      if (cancelled) return;
      setAutostartEnabled(res.enabled);
    });
    void routewardClient.getSystemProxyStatus().then((res) => {
      if (cancelled) return;
      setSystemProxyEnabled(res.enabled);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!diagnostics.daemonConnected) {
      return;
    }
    let cancelled = false;
    void routewardClient.listNamedProfiles().then((list) => {
      if (cancelled) return;
      setNamedProfiles(list);
    });
    return () => {
      cancelled = true;
    };
  }, [diagnostics.daemonConnected, profile.profileId, profile.name]);

  const handleSetNetworkProfileRule = (
    networkName: string,
    profileId: string | null
  ) => {
    setNetworkProfileRules((prev) => {
      const next = { ...prev };
      if (profileId === null) {
        delete next[networkName];
      } else {
        next[networkName] = profileId;
      }
      window.localStorage.setItem(
        UI_CONFIG.STORAGE_KEYS.NETWORK_PROFILE_RULES,
        JSON.stringify(next)
      );
      return next;
    });
  };

  useEffect(() => {
    let cancelled = false;
    const pollNetwork = () => {
      void routewardClient.getCurrentNetworkInfo().then((info) => {
        if (cancelled) return;
        setCurrentNetworkName(info.networkName);
        if (
          info.networkName &&
          diagnostics.daemonConnected &&
          lastAutoSwitchedNetworkRef.current !== info.networkName
        ) {
          const targetProfileId = networkProfileRules[info.networkName];
          if (targetProfileId && targetProfileId !== profile.profileId) {
            lastAutoSwitchedNetworkRef.current = info.networkName;
            void routewardClient
              .switchNamedProfile(targetProfileId)
              .then((switched) => {
                if (cancelled) return;
                pushToast(
                  `${t('app.toast.profile.auto_switched')}: ${switched.name}`,
                  'info'
                );
              })
              .catch(() => {});
          }
        }
      });
    };
    pollNetwork();
    const timer = window.setInterval(
      pollNetwork,
      UI_CONFIG.NETWORK_POLL_INTERVAL_MS
    );
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    diagnostics.daemonConnected,
    networkProfileRules,
    profile.profileId,
    pushToast,
    t
  ]);

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

  const handleResetToDefaults = async () => {
    try {
      const now = new Date();
      const stamp = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      if (diagnostics.daemonConnected) {
        try {
          await routewardClient.saveNamedProfile(undefined, `Backup ${stamp}`);
        } catch {
          // Best-effort backup before resetting defaults.
        }
      }
      await routewardClient.importProfileJson(
        JSON.stringify(DEFAULT_PROFILE_DATA)
      );
      if (diagnostics.daemonConnected) {
        const list = await routewardClient.listNamedProfiles();
        setNamedProfiles(list);
      }
      pushToast(t('app.toast.profile.reset_done'), 'success');
    } catch (err) {
      pushErrorToast(err, 'app.toast.profile.error');
    }
  };

  const policyOrDefault = profile.securityPolicy || {
    killSwitchEnabled: true,
    blockUdpOnTcpOnlyProxy: true,
    strictDnsNoLocalFallback: true
  };

  /** Applies a card and offers an undo that restores the previous switches and rules. */
  const applyUseCase = async (useCase: DashboardUseCaseId) => {
    const plan = planUseCase(useCase, {
      t,
      proxies: profile.proxies,
      chains: profile.chains
    });
    const { changed, previous } = diffSecurityChanges(
      policyOrDefault,
      plan.security
    );
    const previousRules = plan.rules
      .map((rule) => profile.rules.find((r) => r.id === rule.id))
      .filter((rule): rule is RoutingRule => Boolean(rule));
    const createdRuleIds = plan.rules
      .filter((rule) => !profile.rules.some((r) => r.id === rule.id))
      .map((rule) => rule.id);

    try {
      if (changed.length > 0) {
        await routewardClient.updateSecurityPolicy(plan.security);
      }
      for (const rule of plan.rules) {
        await routewardClient.upsertRule(rule);
      }
    } catch (err) {
      pushErrorToast(err);
      return;
    }

    pushToast(
      t(
        plan.skippedProxyRule
          ? 'app.toast.usecase.applied_direct_no_proxy'
          : 'app.toast.usecase.applied'
      ),
      plan.skippedProxyRule ? 'info' : 'success',
      {
        label: t('app.toast.undo'),
        onAction: () => {
          runMutation(
            async () => {
              if (changed.length > 0) {
                await routewardClient.updateSecurityPolicy(previous);
              }
              for (const id of createdRuleIds) {
                await routewardClient.removeRule(id);
              }
              for (const rule of previousRules) {
                await routewardClient.upsertRule(rule);
              }
            },
            () => pushToast(t('app.toast.undo_applied'), 'info')
          );
        }
      }
    );
  };

  /** Several settings change at once, so a plain-language summary is shown first. */
  const handleApplyUseCase = (useCase: DashboardUseCaseId) => {
    const plan = planUseCase(useCase, {
      t,
      proxies: profile.proxies,
      chains: profile.chains
    });
    if (
      isUseCaseApplied(
        useCase,
        policyOrDefault,
        profile.rules,
        profile.proxies,
        profile.chains
      )
    ) {
      pushToast(t('app.toast.usecase.already_applied'), 'info');
      return;
    }
    const { changed } = diffSecurityChanges(policyOrDefault, plan.security);
    const newRules = plan.rules.filter(
      (rule) => !profile.rules.some((r) => r.id === rule.id && r.enabled)
    );
    setPendingConfirm({
      title: t('dashboard.confirm.usecase_title', {
        name: t(`dashboard.simple.uc_${useCase}_title`)
      }),
      intro: t('dashboard.confirm.intro'),
      changes: [
        ...changed.map((key) => t(SHIELD_SETTING_LABEL_KEYS[key])),
        ...newRules.map((rule) =>
          t('dashboard.confirm.rule_line', { name: rule.name })
        )
      ],
      onConfirm: () => {
        void applyUseCase(useCase);
      }
    });
  };

  /** The all-in-one shield: turning it on asks first, turning it off restores the earlier mix. */
  const handleToggleAllShields = (next: boolean) => {
    const plan = planShieldToggle(policyOrDefault, next, rememberedShieldMix);
    const apply = () => {
      runMutation(
        () => routewardClient.updateSecurityPolicy(plan.apply),
        () => {
          setRememberedShieldMix(plan.remember);
          pushToast(
            t(
              next
                ? 'app.toast.shield.turned_on'
                : 'app.toast.shield.turned_off'
            ),
            next ? 'success' : 'info',
            {
              label: t('app.toast.undo'),
              onAction: () => {
                runMutation(
                  () => routewardClient.updateSecurityPolicy(plan.undo),
                  () => {
                    setRememberedShieldMix(next ? null : rememberedShieldMix);
                    pushToast(t('app.toast.undo_applied'), 'info');
                  }
                );
              }
            }
          );
        }
      );
    };
    if (!next) {
      apply();
      return;
    }
    const { changed } = diffSecurityChanges(policyOrDefault, plan.apply);
    setPendingConfirm({
      title: t('dashboard.confirm.shield_title'),
      intro: t('dashboard.confirm.intro'),
      changes: changed.map((key) => t(SHIELD_SETTING_LABEL_KEYS[key])),
      onConfirm: apply
    });
  };

  const [unreachableProxyIds, setUnreachableProxyIds] = useState<string[]>([]);
  const [reachableProxyIds, setReachableProxyIds] = useState<string[]>([]);

  /** Remembers which proxies failed their last test (the daemon keeps no failure flag). */
  const recordProxyTestReport = (
    proxyId: string,
    report: { reachable: boolean } | null
  ) => {
    if (!report) return;
    setUnreachableProxyIds((prev) => {
      const without = prev.filter((id) => id !== proxyId);
      return report.reachable ? without : [...without, proxyId];
    });
    setReachableProxyIds((prev) => {
      const without = prev.filter((id) => id !== proxyId);
      return report.reachable ? [...without, proxyId] : without;
    });
  };

  const testAndRecordProxy = async (proxyId: string) => {
    const report = await routewardClient.testProxy(proxyId).catch(() => null);
    recordProxyTestReport(proxyId, report);
    return report;
  };

  /** Tests every enabled proxy that appeared since `knownIds`, like a proxy added by hand. */
  const testAddedProxies = (knownIds: Set<string>) => {
    if (!diagnostics.daemonConnected) return;
    routewardClient
      .getProfile()
      .proxies.filter((p) => p.enabled && !knownIds.has(p.id))
      .forEach((p) => {
        void testAndRecordProxy(p.id);
      });
  };

  const handleToggleSimpleFailover = async (
    enabled: boolean,
    chain: ProxyChain | null
  ) => {
    // Only the chain managed by the Simple screen is touched: Expert chains are never adopted.
    if (!chain || chain.id !== UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID) return;
    try {
      if (enabled) {
        await routewardClient.upsertChain(chain);
        const rulesToMigrate = profile.rules.filter(
          (r) => isSimpleCreatedRuleId(r.id) && r.action.type === 'proxy'
        );
        for (const rule of rulesToMigrate) {
          await routewardClient.upsertRule({
            ...rule,
            action: { type: 'chain', targetId: chain.id }
          });
        }
        pushToast(t('proxies.simple.failover_applied_toast'), 'success');
      } else {
        const primaryProxyId = profile.proxies.find((p) => p.enabled)?.id;
        // Every rule that still points at the chain must move before the chain disappears.
        const rulesToRestore = profile.rules.filter(
          (r) => r.action.type === 'chain' && r.action.targetId === chain.id
        );
        for (const rule of rulesToRestore) {
          await routewardClient.upsertRule(
            primaryProxyId
              ? { ...rule, action: { type: 'proxy', targetId: primaryProxyId } }
              : { ...rule, enabled: false }
          );
        }
        await routewardClient.removeChain(chain.id);
        const disabledCount = primaryProxyId
          ? 0
          : rulesToRestore.filter((r) => r.enabled).length;
        pushToast(
          disabledCount > 0
            ? t('proxies.simple.failover_disabled_rules_toast', {
                count: disabledCount
              })
            : t('proxies.simple.failover_disabled_toast'),
          'info'
        );
      }
    } catch (err) {
      pushErrorToast(err);
    }
  };

  const handleRemoveProxyWithCleanup = async (proxyId: string) => {
    const removedProxy = profile.proxies.find((p) => p.id === proxyId) ?? null;
    const plan = planProxyRemoval(
      proxyId,
      profile.proxies,
      profile.chains,
      profile.rules
    );
    const removedFailoverChain = plan.removeFailoverChain
      ? (profile.chains.find((c) => c.id === UI_CONFIG.SIMPLE_FAILOVER_CHAIN_ID) ??
        null)
      : null;
    try {
      // Rules first: they move to the new primary proxy, or are turned off when none is left.
      // They are never switched to a direct connection (that would expose the real IP address).
      for (const rule of plan.affectedRules) {
        await routewardClient.upsertRule(applyProxyRemovalToRule(rule, plan));
      }
      if (removedFailoverChain) {
        await routewardClient.removeChain(removedFailoverChain.id);
      }
      await routewardClient.removeProxy(proxyId);
      setUnreachableProxyIds((prev) => prev.filter((id) => id !== proxyId));

      let message = t('app.toast.proxy.deleted');
      if (plan.newPrimary && plan.affectedRules.length > 0) {
        message = t('proxies.delete.toast_retargeted', {
          count: plan.affectedRules.length,
          name: plan.newPrimary.name
        });
      } else if (!plan.newPrimary && plan.affectedEnabledCount > 0) {
        message = t('proxies.delete.toast_disabled', {
          count: plan.affectedEnabledCount
        });
      }

      // The UI never holds a proxy password: a restored proxy needs it typed again.
      const hadPassword = Boolean(removedProxy?.auth?.hasPassword);
      const restoredProxy = removedProxy
        ? {
            ...removedProxy,
            auth: removedProxy.auth
              ? {
                  username: removedProxy.auth.username,
                  hasPassword: false
                }
              : null
          }
        : null;
      pushToast(
        message,
        'warning',
        restoredProxy
          ? {
              label: t('app.toast.undo'),
              onAction: () => {
                runMutation(
                  async () => {
                    await routewardClient.upsertProxy(restoredProxy);
                    if (removedFailoverChain) {
                      await routewardClient.upsertChain(removedFailoverChain);
                    }
                    for (const rule of plan.affectedRules) {
                      await routewardClient.upsertRule(rule);
                    }
                  },
                  () =>
                    pushToast(
                      hadPassword
                        ? t('proxies.delete.undo_password_needed')
                        : t('app.toast.undo_applied'),
                      hadPassword ? 'warning' : 'info'
                    )
                );
              }
            }
          : undefined
      );
    } catch (err) {
      pushErrorToast(err);
    }
  };

  const handleSetPrimaryProxy = async (proxyId: string) => {
    const oldPrimaryId = profile.proxies.find((p) => p.enabled)?.id;
    try {
      await routewardClient.setPrimaryProxy(proxyId);
      const newPrimaryId = routewardClient
        .getProfile()
        .proxies.find((p) => p.enabled)?.id;
      // Only rules created from Simple screens follow the primary proxy: Expert rules stay put.
      let movedCount = 0;
      if (oldPrimaryId && newPrimaryId === proxyId && oldPrimaryId !== proxyId) {
        const rulesToMove = profile.rules.filter(
          (r) =>
            isSimpleCreatedRuleId(r.id) &&
            r.action.type === 'proxy' &&
            r.action.targetId === oldPrimaryId
        );
        for (const rule of rulesToMove) {
          await routewardClient.upsertRule({
            ...rule,
            action: { type: 'proxy', targetId: proxyId }
          });
          movedCount += 1;
        }
      }
      pushToast(
        movedCount > 0
          ? t('proxies.primary.toast_rules_moved', { count: movedCount })
          : t('app.toast.proxy.primary_changed'),
        'success'
      );
    } catch (err) {
      pushErrorToast(err);
    }
  };

  const handlePasteProxyFromClipboard = async () => {
    if (!navigator.clipboard || typeof navigator.clipboard.readText !== 'function') {
      pushToast(t('app.toast.proxy.clipboard_empty'), 'warning');
      return;
    }
    try {
      const raw = normalizeProxyImportText(
        (await navigator.clipboard.readText()).trim(),
        UI_CONFIG.DEFAULT_LINK_PROXY_PROTOCOL
      );
      if (!raw || !raw.includes('://')) {
        pushToast(t('app.toast.proxy.clipboard_empty'), 'warning');
        return;
      }
      const beforeIds = new Set(profile.proxies.map((p) => p.id));
      const count = await routewardClient.importProxyUris(raw);
      if (count > 0) {
        pushToast(`${t('app.toast.proxy.imported_uris')} (${count})`, 'success');
        testAddedProxies(beforeIds);
      } else {
        pushToast(t('app.toast.proxy.clipboard_empty'), 'warning');
      }
    } catch (err) {
      pushErrorToast(err);
    }
  };

  /** "Let through" from the troubleshooter: one direct rule per app or site, with an undo. */
  const allowDirect = (params: {
    id: string;
    name: string;
    processPatterns: string[];
    domainPatterns: string[];
    toastKey: string;
    subject: string;
  }) => {
    const previousRule = profile.rules.find((r) => r.id === params.id) ?? null;
    runMutation(
      () =>
        routewardClient.upsertRule({
          id: params.id,
          name: params.name,
          enabled: true,
          priority: UI_CONFIG.TROUBLESHOOT_RULE_PRIORITY,
          processPatterns: params.processPatterns,
          domainPatterns: params.domainPatterns,
          ipCidrs: [],
          portRanges: [],
          protocol: 'any',
          action: { type: 'direct' }
        }),
      () => {
        pushToast(t(params.toastKey, { name: params.subject }), 'success', {
          label: t('app.toast.undo'),
          onAction: () => {
            runMutation(
              () =>
                previousRule
                  ? routewardClient.upsertRule(previousRule)
                  : routewardClient.removeRule(params.id),
              () => pushToast(t('app.toast.undo_applied'), 'info')
            );
          }
        });
        setShowTroubleshootModal(false);
      }
    );
  };

  /** The setup is saved: the assistant no longer opens by itself. Closing it does not count. */
  const markWizardCompleted = () => {
    try {
      window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.WIZARD_COMPLETED, 'true');
    } catch {
      // Storage can be unavailable; the assistant then simply offers itself again.
    }
    setWizardCompleted(true);
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

  const handleDroppedFile = (file: File) => {
    const lowerName = file.name.toLowerCase();
    const isJson = lowerName.endsWith('.json') || file.type === 'application/json';
    const isText =
      lowerName.endsWith('.txt') ||
      lowerName.endsWith('.uri') ||
      file.type === 'text/plain';
    if (!isJson && !isText) {
      pushToast(t('app.dropzone.unsupported'), 'warning');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result !== 'string') return;
      const content = reader.result.trim();
      if (!content) return;
      if (isText) {
        runMutation(
          () => routewardClient.importProxyUris(content),
          (count) => {
            if (count > 0) {
              pushToast(`${t('app.toast.proxy.imported_uris')} (${count})`);
            } else {
              pushToast(t('app.toast.proxy.clipboard_empty'), 'warning');
            }
          }
        );
        return;
      }
      try {
        const parsed = JSON.parse(content) as Record<string, unknown>;
        const isFoxyProxy =
          Array.isArray(parsed?.data) ||
          Boolean(parsed?.proxyPatterns) ||
          (typeof parsed?.mode === 'string' && !parsed?.profileId);
        if (isFoxyProxy) {
          void routewardClient
            .importFoxyProxyJson(content, [])
            .then((res) => {
              pushToast(
                `${t('app.toast.foxyproxy.imported')} (${res.rules.length})`,
                'success'
              );
            })
            .catch((err: unknown) => {
              pushErrorToast(err, 'app.toast.foxyproxy.import_error');
            });
        } else {
          void routewardClient
            .importProfileJson(content)
            .then(() => {
              pushToast(t('app.toast.profile.imported'));
            })
            .catch((err: unknown) => {
              pushErrorToast(err, 'app.toast.profile.import_error');
            });
        }
      } catch {
        pushToast(t('app.toast.profile.import_error'), 'error');
      }
    };
    reader.onerror = () => {
      pushToast(t('app.toast.profile.import_error'), 'error');
    };
    reader.readAsText(file);
  };

  const securityPolicy = policyOrDefault;

  const isEngineRunning = diagnostics.daemonConnected && diagnostics.running;
  const activePrimaryProxy = profile.proxies.find((p) => p.enabled) ?? null;

  const [activitySubtab, setActivitySubtab] =
    useState<ActivitySubtab>('connections');
  const [logsJump, setLogsJump] = useState<LogsJump | null>(null);
  const [diagnosticsRequest, setDiagnosticsRequest] = useState<{
    tab: 'logs' | 'checkup';
  } | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzed, setAnalyzed] = useState(false);
  const [analyzerError, setAnalyzerError] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const logsJumpSeq = useRef(0);

  const loadBlocked = useCallback(() => routewardClient.getBlocked(), []);
  const blocked = useBlockedSummary(
    activeTab === 'activity' && activitySubtab === 'blocked',
    loadBlocked
  );
  const queryLogs = useCallback(
    (req: QueryLogsRequest) => routewardClient.queryLogs(req),
    []
  );

  const openBlockedTab = () => {
    setActivitySubtab('blocked');
    setActiveTab('activity');
  };

  const openLogsFor = (target: {
    connectionId?: string;
    pid?: number;
    centerMs: number;
  }) => {
    logsJumpSeq.current += 1;
    setLogsJump({ ...target, nonce: logsJumpSeq.current });
    setDiagnosticsRequest({ tab: 'logs' });
    setActiveTab('settings');
  };

  const runAnalyzer = () => {
    setAnalyzing(true);
    setAnalyzerError(false);
    routewardClient
      .analyzeDiagnostics()
      .then((res) => {
        setFindings(res.findings ?? []);
        setAnalyzed(true);
      })
      .catch(() => setAnalyzerError(true))
      .finally(() => setAnalyzing(false));
  };

  const openCheckup = () => {
    setDiagnosticsRequest({ tab: 'checkup' });
    setActiveTab('settings');
    runAnalyzer();
  };

  const handleFix = (fix: FixAction) => {
    switch (fix.type) {
      case 'openProxy':
        setActiveTab('proxy');
        break;
      case 'testProxy':
        void testAndRecordProxy(fix.id).then((report) => {
          setProxyOutageDetected(!report?.reachable);
          pushToast(
            report?.reachable
              ? t('app.toast.proxy.tested')
              : t('app.toast.proxy.unreachable'),
            report?.reachable ? 'success' : 'error'
          );
        });
        break;
      case 'unblock':
        openBlockedTab();
        break;
      case 'editRule':
        setActiveTab('apps');
        break;
      case 'pauseProtection':
        void handleTemporaryPause(UI_CONFIG.OUTAGE_PAUSE_MINUTES);
        break;
      case 'openSetting':
        setActiveTab('settings');
        break;
      default:
        break;
    }
  };

  const unblockFlow = useUnblockFlow({
    rules: profile.rules,
    proxies: profile.proxies,
    chains: profile.chains,
    t,
    previewRuleChange: (req) => routewardClient.previewRuleChange(req),
    upsertRule: (rule) => routewardClient.upsertRule(rule),
    removeRule: (ruleId) => routewardClient.removeRule(ruleId),
    onCommand: (command, target) => {
      switch (command) {
        case 'testProxy': {
          const proxyId = target.proxyId ?? activePrimaryProxy?.id;
          if (proxyId) handleFix({ type: 'testProxy', id: proxyId });
          break;
        }
        case 'openProxy':
          setActiveTab('proxy');
          break;
        case 'pause':
          void handleTemporaryPause(UI_CONFIG.OUTAGE_PAUSE_MINUTES);
          break;
        case 'flushDns':
          runMutation(
            () => routewardClient.flushFakeIps(),
            () => pushToast(t('app.toast.dns.flushed'), 'info')
          );
          break;
        default:
          break;
      }
    },
    notify: pushToast,
    onError: (err) => pushErrorToast(err)
  });
  const proxyReachability = resolveProxyReachability(
    activePrimaryProxy,
    unreachableProxyIds,
    reachableProxyIds,
    proxyOutageDetected
  );
  const health = computeProtectionHealth({
    diagnostics,
    primaryProxy: activePrimaryProxy,
    proxyReachability
  });
  const healthTexts = PROTECTION_HEALTH_TEXTS[health.state];
  const healthTime =
    health.pausedUntilEpochMs !== null
      ? formatPauseEnd(health.pausedUntilEpochMs, i18n.language)
      : '';

  // A different primary proxy starts with a clean slate: the old outage no longer applies.
  const primaryProxyId = activePrimaryProxy?.id ?? null;
  useEffect(() => {
    setProxyOutageDetected(false);
    setOutageDismissedForKey(null);
  }, [primaryProxyId]);
  const recentKillSwitchFailure = connections.find(
    (c) =>
      c.status === 'blocked' &&
      Boolean(c.errorDetail) &&
      /kill-?switch|upstream|proxy|timeout|unreachable/i.test(c.errorDetail || '')
  );
  const outageKey =
    proxyOutageDetected && activePrimaryProxy
      ? `probe:${activePrimaryProxy.id}`
      : recentKillSwitchFailure
        ? `conn:${recentKillSwitchFailure.id}`
        : null;
  const showProxyOutageBanner =
    isEngineRunning &&
    Boolean(activePrimaryProxy) &&
    Boolean(outageKey) &&
    outageKey !== outageDismissedForKey;

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

  const statusPillClass =
    health.tone === 'ok'
      ? 'bg-tf-green/15 text-tf-green border-tf-green/40'
      : health.tone === 'warn'
        ? 'bg-tf-orange/15 text-tf-orange border-tf-orange/40'
        : 'bg-tf-red/15 text-tf-red border-tf-red/40';
  const statusDotClass =
    health.tone === 'ok'
      ? 'bg-tf-green'
      : health.tone === 'warn'
        ? 'bg-tf-orange'
        : 'bg-tf-red';
  const statusPillText = t(healthTexts.pill, { time: healthTime });

  return (
    <div
      className="relative flex min-h-screen flex-col bg-tf-bg text-tf-primary"
      onDragEnter={(e) => {
        if (e.dataTransfer?.types?.includes('Files')) {
          e.preventDefault();
          dragDepthRef.current += 1;
          setDraggingFile(true);
        }
      }}
      onDragOver={(e) => {
        if (e.dataTransfer?.types?.includes('Files')) {
          e.preventDefault();
        }
      }}
      onDragLeave={(e) => {
        if (e.dataTransfer?.types?.includes('Files')) {
          e.preventDefault();
          dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
          if (dragDepthRef.current === 0) {
            setDraggingFile(false);
          }
        }
      }}
      onDrop={(e) => {
        e.preventDefault();
        dragDepthRef.current = 0;
        setDraggingFile(false);
        const dropped = e.dataTransfer?.files?.[0];
        if (dropped) {
          handleDroppedFile(dropped);
        }
      }}
    >
      {draggingFile && (
        <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm">
          <div className="tf-card flex max-w-md flex-col items-center gap-2 border-2 border-dashed border-tf-accent p-8 text-center shadow-2xl">
            <Sparkles className="h-8 w-8 text-tf-accent" />
            <div className="text-base font-bold text-tf-primary">
              {t('app.dropzone.title')}
            </div>
            <p className="text-xs text-tf-secondary">
              {t('app.dropzone.subtitle')}
            </p>
          </div>
        </div>
      )}
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
                  <span className={`h-1.5 w-1.5 rounded-full ${statusDotClass}`} />
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

            {experienceMode === 'simple' && (
              <button
                type="button"
                onClick={() => setShowGlossaryModal(true)}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-secondary hover:border-tf-accent hover:text-tf-primary"
              >
                <BookOpen className="h-3.5 w-3.5 text-tf-accent" />
                <span>{t('app.help.glossary_button')}</span>
              </button>
            )}

            {/* Primary Enable / Pause Protection CTA (hidden on Simple Home where hero CTA leads) */}
            {!(experienceMode === 'simple' && activeTab === 'home') && (
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
            )}
          </div>
        </div>
      </header>

      {/* Persistent Daemon Disconnected / Non-Elevated Warning Banner */}
      {!diagnostics.daemonConnected &&
        !(experienceMode === 'simple' && activeTab === 'home') && (
        <div className="border-b border-tf-red/40 bg-tf-red/15 px-6 py-2.5">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-xs lg:flex-nowrap">
            <div className="flex items-center gap-2.5 lg:min-w-0 lg:flex-1">
              <AlertTriangle className="h-4 w-4 shrink-0 text-tf-red" />
              <div>
                <span className="font-bold text-tf-red">
                  {experienceMode === 'simple'
                    ? t('app.daemon_banner.simple_disconnected_title')
                    : t('app.daemon_banner.disconnected_title')}
                </span>{' '}
                <span className="text-tf-primary">
                  -{' '}
                  {experienceMode === 'simple'
                    ? diagnostics.osName === 'WINDOWS'
                      ? t('app.daemon_banner.simple_disconnected_desc')
                      : t('app.daemon_banner.simple_disconnected_non_windows')
                    : t('app.daemon_banner.disconnected_desc')}
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
                    void handleStartFromHome();
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
            <div className="min-w-0 flex-1">
              <span className="font-bold text-tf-orange">
                {t('app.daemon_banner.not_elevated_title')}
              </span>{' '}
              <span className="text-tf-primary">
                - {t('app.daemon_banner.not_elevated_desc')}
              </span>
            </div>
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
                  : t('app.daemon_banner.not_elevated_button')}
              </button>
            )}
          </div>
        </div>
      )}

      {activeTab === 'home' &&
        diagnostics.daemonConnected &&
        !diagnostics.running &&
        diagnostics.autoStartErrorKey !== null &&
        i18n.exists(diagnostics.autoStartErrorKey) && (
          <div
            role="alert"
            className="border-b border-tf-red/40 bg-tf-red/15 px-6 py-2.5"
          >
            <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2.5">
                <AlertTriangle className="h-4 w-4 shrink-0 text-tf-red" />
                <div>
                  <span className="font-bold text-tf-red">
                    {t('app.auto_start_error.title')}
                  </span>{' '}
                  <span className="text-tf-primary">
                    - {t(diagnostics.autoStartErrorKey)}
                  </span>
                </div>
              </div>
              <button
                type="button"
                disabled={togglingEngine}
                onClick={() => {
                  void handleToggleEngine(true);
                }}
                className="tf-btn-accent px-3 py-1 text-xs disabled:opacity-60"
              >
                {t('app.auto_start_error.retry')}
              </button>
            </div>
          </div>
        )}

      {showServiceNotice && (
        <div role="status" className="border-b border-tf-cyan/40 bg-tf-cyan/10 px-6 py-2.5">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-xs">
            <div>
              <span className="font-bold text-tf-cyan">
                {t('app.service_notice.title')}
              </span>{' '}
              <span className="text-tf-primary">
                - {t('app.service_notice.desc')}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowServiceNotice(false)}
              className="tf-surface-alt px-3 py-1 text-xs font-semibold text-tf-primary hover:border-tf-accent"
            >
              {t('app.service_notice.dismiss')}
            </button>
          </div>
        </div>
      )}

      {showProxyOutageBanner && outageKey && (
        <div
          role="alert"
          className="border-b border-tf-orange/50 bg-tf-orange/15 px-6 py-2.5"
        >
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0 text-tf-orange" />
              <div>
                <span className="font-bold text-tf-orange">
                  {securityPolicy.killSwitchEnabled
                    ? t('app.outage_banner.title')
                    : t('app.outage_banner.title_no_killswitch')}
                </span>{' '}
                <span className="text-tf-primary">
                  -{' '}
                  {securityPolicy.killSwitchEnabled
                    ? t('app.outage_banner.desc')
                    : t('app.outage_banner.desc_no_killswitch')}
                </span>
              </div>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  void handleTemporaryPause(UI_CONFIG.OUTAGE_PAUSE_MINUTES);
                  setOutageDismissedForKey(outageKey);
                }}
                className="tf-btn-accent px-3 py-1 text-xs"
              >
                {t('app.outage_banner.pause_15m', {
                  minutes: UI_CONFIG.OUTAGE_PAUSE_MINUTES
                })}
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('proxy')}
                className="tf-surface-alt px-2.5 py-1 text-xs font-semibold text-tf-primary hover:border-tf-accent"
              >
                {t('app.outage_banner.check_proxy')}
              </button>
              <button
                type="button"
                onClick={() => {
                  setOutageDismissedForKey(outageKey);
                  setProxyOutageDetected(false);
                }}
                className="rounded px-2 py-1 text-xs text-tf-secondary hover:text-tf-primary"
              >
                {t('app.outage_banner.dismiss')}
              </button>
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
            chains={profile.chains}
            rules={profile.rules}
            health={health}
            verifyRequestId={verifyRequestId}
            startingProtection={startingDaemon || togglingEngine}
            onToggleEngine={() => {
              void handleToggleEngine(!isEngineRunning);
            }}
            onTemporaryPause={handleTemporaryPause}
            onStartAndEnableProtection={handleStartFromHome}
            onApplyUseCase={handleApplyUseCase}
            onTestPrimaryProxy={async (proxyId) => {
              try {
                const report = await routewardClient.testProxy(proxyId);
                recordProxyTestReport(proxyId, report);
                if (report?.reachable) {
                  setProxyOutageDetected(false);
                  pushToast(t('app.toast.proxy.tested'), 'success');
                } else {
                  setProxyOutageDetected(true);
                  pushToast(t('app.toast.proxy.unreachable'), 'error');
                }
                return report;
              } catch (err) {
                setProxyOutageDetected(true);
                pushErrorToast(err);
                return null;
              }
            }}
            onCheckDirectIp={() => routewardClient.getDirectIp()}
            onPasteFromClipboard={handlePasteProxyFromClipboard}
            onNavigateProxy={() => setActiveTab('proxy')}
            onUpdateSecurityPolicy={(partial) => {
              runMutation(() => routewardClient.updateSecurityPolicy(partial));
            }}
            onOpenWizard={() => setShowWizardModal(true)}
            onOpenTroubleshoot={() => setShowTroubleshootModal(true)}
            onOpenBlocked={openBlockedTab}
            onNavigateRules={() => setActiveTab('apps')}
            onSwitchToExpert={() => handleSetExperienceMode('expert')}
          />
        )}

        {activeTab === 'apps' && (
          <RulesView
            rules={profile.rules}
            proxies={profile.proxies}
            chains={profile.chains}
            osName={diagnostics.osName}
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
              const removedRule = profile.rules.find((r) => r.id === id) ?? null;
              runMutation(
                () => routewardClient.removeRule(id),
                () =>
                  pushToast(
                    t('app.toast.rule.deleted'),
                    'warning',
                    removedRule
                      ? {
                          label: t('app.toast.undo'),
                          onAction: () => {
                            runMutation(
                              () => routewardClient.upsertRule(removedRule),
                              () => pushToast(t('app.toast.undo_applied'), 'info')
                            );
                          }
                        }
                      : undefined
                  )
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
            rules={profile.rules}
            unreachableProxyIds={unreachableProxyIds}
            experienceMode={experienceMode}
            onDetectExistingProxies={() =>
              routewardClient.detectExistingProxiesStrict()
            }
            onTestProxy={async (id) => {
              try {
                const report = await routewardClient.testProxy(id);
                recordProxyTestReport(id, report);
                if (report?.reachable) {
                  pushToast(t('app.toast.proxy.tested'), 'success');
                } else {
                  pushToast(t('app.toast.proxy.unreachable'), 'error');
                }
              } catch (err) {
                pushErrorToast(err);
              }
            }}
            onTestAllProxies={async () => {
              try {
                const reports = await routewardClient.testAllProxies();
                reports.forEach((report) =>
                  recordProxyTestReport(report.proxyId, report)
                );
                pushToast(t('app.toast.proxy.tested'));
              } catch (err) {
                pushErrorToast(err);
              }
            }}
            onAddProxy={(node) => {
              const isNewProxy = !profile.proxies.some((p) => p.id === node.id);
              runMutation(
                () => routewardClient.upsertProxy(node),
                () => {
                  pushToast(t('app.toast.proxy.added'));
                  if (
                    isNewProxy &&
                    node.enabled &&
                    diagnostics.daemonConnected
                  ) {
                    void testAndRecordProxy(node.id);
                  }
                }
              );
            }}
            onImportUris={(text) => {
              const knownIds = new Set(profile.proxies.map((p) => p.id));
              runMutation(
                () => routewardClient.importProxyUris(text),
                (count) => {
                  if (count > 0) {
                    pushToast(
                      `${t('app.toast.proxy.imported_uris')} (${count})`
                    );
                    testAddedProxies(knownIds);
                  } else {
                    pushToast(t('proxies.import.none_added'), 'warning');
                  }
                }
              );
            }}
            onCopyUri={() => {
              pushToast(t('app.toast.proxy.copied_uri'), 'info');
            }}
            onRemoveProxy={(id) => {
              void handleRemoveProxyWithCleanup(id);
            }}
            onAddChain={(chain) => {
              runMutation(() => routewardClient.upsertChain(chain));
            }}
            onRemoveChain={(id) => {
              runMutation(() => routewardClient.removeChain(id));
            }}
            onToggleSimpleFailover={handleToggleSimpleFailover}
            onSetPrimaryProxy={handleSetPrimaryProxy}
            onPasteFromClipboard={handlePasteProxyFromClipboard}
          />
        )}

        {activeTab === 'activity' && (
          <ActivitySubtabs
            value={activitySubtab}
            onChange={setActivitySubtab}
            blockedCount={telemetry.blockedCount}
          />
        )}

        {activeTab === 'activity' && activitySubtab === 'blocked' && (
          <BlockedView
            entries={blocked.entries}
            counters={blocked.counters}
            rules={profile.rules}
            proxies={profile.proxies}
            chains={profile.chains}
            loading={blocked.loading}
            error={blocked.error}
            onRefresh={blocked.refresh}
            onChoose={(target, option, duration) => {
              void unblockFlow.choose(target, option, duration);
            }}
            onSeeLogs={(entry) =>
              openLogsFor({
                connectionId: entry.lastConnectionId,
                pid: entry.lastPid,
                centerMs: Date.parse(entry.lastSeen)
              })
            }
            onOpenCheckup={openCheckup}
          />
        )}

        {activeTab === 'activity' && activitySubtab === 'connections' && (
          <ConnectionsView
            connections={connections}
            proxies={profile.proxies}
            chains={profile.chains}
            rules={profile.rules}
            experienceMode={experienceMode}
            engineRunning={isEngineRunning}
            onEnableProtection={() => {
              if (diagnostics.daemonConnected) {
                void handleToggleEngine(true);
              } else if (diagnostics.osName === 'WINDOWS') {
                void handleStartAndEnableProtection();
              }
            }}
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
            onSeeLogs={(conn) =>
              openLogsFor({
                connectionId: conn.id,
                pid: conn.pid,
                centerMs: Date.parse(conn.startedAt)
              })
            }
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
            onToggleAllShields={handleToggleAllShields}
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
            onQueryLogs={queryLogs}
            logsJump={logsJump}
            diagnosticsRequest={diagnosticsRequest}
            checkupPanel={
              <AnalyzerPanel
                findings={findings}
                proxies={profile.proxies}
                rules={profile.rules}
                loading={analyzing}
                error={analyzerError}
                analyzed={analyzed}
                onRun={runAnalyzer}
                onFix={handleFix}
                onExport={() => setShowExportModal(true)}
              />
            }
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
            onResetToDefaults={handleResetToDefaults}
            currentNetworkName={currentNetworkName}
            networkProfileRules={networkProfileRules}
            onSetNetworkProfileRule={handleSetNetworkProfileRule}
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
              {toast.actionLabel && toast.onAction && (
                <button
                  type="button"
                  onClick={() => {
                    toast.onAction?.();
                    dismissToast(toast.id);
                  }}
                  className="ml-1 rounded-tf-sm bg-tf-accent/20 px-2 py-0.5 text-[11px] font-bold text-tf-accent transition hover:bg-tf-accent/30"
                >
                  {toast.actionLabel}
                </button>
              )}
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
        <GlossaryModal
          experienceMode={experienceMode}
          onClose={() => setShowGlossaryModal(false)}
        />
      )}

      {showTroubleshootModal && (
        <TroubleshootModal
          connections={connections}
          health={health}
          onTestProxy={() => {
            if (activePrimaryProxy) {
              void testAndRecordProxy(activePrimaryProxy.id).then((report) => {
                setProxyOutageDetected(!report?.reachable);
                pushToast(
                  report?.reachable
                    ? t('app.toast.proxy.tested')
                    : t('app.toast.proxy.unreachable'),
                  report?.reachable ? 'success' : 'error'
                );
              });
            }
          }}
          onPauseProtection={(minutes) => {
            void handleTemporaryPause(minutes);
            setShowTroubleshootModal(false);
          }}
          onChangeProxy={() => {
            setShowTroubleshootModal(false);
            setActiveTab('proxy');
          }}
          onAllowAppDirect={(conn) => {
            const name = getFriendlyAppName(conn.processName).displayName;
            allowDirect({
              id: `rule-unblock-app-${slugifyRuleKey(conn.processName)}`,
              name: t('troubleshoot.rules.app_direct', { name }),
              processPatterns: [conn.processName],
              domainPatterns: [],
              toastKey: 'troubleshoot.toast.app_allowed',
              subject: name
            });
          }}
          onAllowSiteDirect={(conn) => {
            const domain = conn.resolvedDomain || conn.targetHost;
            allowDirect({
              id: `rule-unblock-site-${slugifyRuleKey(domain)}`,
              name: t('troubleshoot.rules.site_direct', { name: domain }),
              processPatterns: [],
              domainPatterns: [domain],
              toastKey: 'troubleshoot.toast.site_allowed',
              subject: domain
            });
          }}
          onClose={() => setShowTroubleshootModal(false)}
        />
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
          onAddProxy={async (node) => {
            await routewardClient.upsertProxy(node);
            return routewardClient.getProfile().proxies;
          }}
          onRemoveProxy={(proxyId) => routewardClient.removeProxy(proxyId)}
          onSetPrimaryProxy={async (proxyId) => {
            await routewardClient.setPrimaryProxy(proxyId);
            return routewardClient.getProfile().proxies;
          }}
          onTestProxy={(proxyId) => testAndRecordProxy(proxyId)}
          onDetectExistingProxies={() =>
            routewardClient.detectExistingProxiesStrict()
          }
          onEnableProtection={async () => {
            const current = routewardClient.getDiagnostics();
            if (!current.daemonConnected) {
              return false;
            }
            if (current.running) {
              return true;
            }
            return handleToggleEngine(true);
          }}
          onAddRule={(rule) => routewardClient.upsertRule(rule)}
          onSelectMode={(mode) => handleSetExperienceMode(mode)}
          onError={(err) => pushErrorToast(err)}
          onComplete={(hasEnabledProxy) => {
            markWizardCompleted();
            pushToast(
              t(
                hasEnabledProxy === false
                  ? 'app.toast.wizard.completed_direct_no_proxy'
                  : 'app.toast.wizard.completed'
              ),
              hasEnabledProxy === false ? 'info' : 'success'
            );
          }}
          onConfigSaved={markWizardCompleted}
          onVerifyProtection={() => {
            setShowWizardModal(false);
            setActiveTab('home');
            setVerifyRequestId((prev) => prev + 1);
          }}
          onClose={() => setShowWizardModal(false)}
        />
      )}

      {unblockFlow.element}

      {showExportModal && (
        <DiagnosticExportModal
          onCollect={(req) => routewardClient.collectDiagnostics(req)}
          onClose={() => setShowExportModal(false)}
          onDownloaded={(fileName) => {
            setShowExportModal(false);
            pushToast(t('diagnostics.export.done', { name: fileName }), 'success');
          }}
        />
      )}

      {pendingConfirm && (
        <ConfirmApplyModal
          title={pendingConfirm.title}
          intro={pendingConfirm.intro}
          changes={pendingConfirm.changes}
          onConfirm={() => {
            const confirmed = pendingConfirm;
            setPendingConfirm(null);
            confirmed.onConfirm();
          }}
          onCancel={() => setPendingConfirm(null)}
        />
      )}

      {showLauncherModal && (
        <ProcessLauncherModal
          relayEndpoint={diagnostics.relayTcpEndpoint}
          relayHttpEndpoint={diagnostics.relayHttpEndpoint}
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
          experienceMode={experienceMode}
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
