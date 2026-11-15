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

import React, { useRef, useState } from 'react';
import {
  Activity,
  BookOpen,
  Cpu,
  Download,
  FileText,
  Globe,
  HardDrive,
  Languages,
  Palette,
  Rocket,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Upload,
  Wand2
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  AccentTint,
  FakeIpEntry,
  InterceptionMode,
  LogEntry,
  SecurityPolicyConfig,
  SystemDiagnostics
} from '../types/routeward';
import { DnsView } from './DnsView';
import { HelpTooltip } from './HelpTooltip';
import { LogsView } from './LogsView';
import { ExperienceMode } from './QuickSetupWizardModal';

interface SettingsViewProps {
  diagnostics: SystemDiagnostics;
  securityPolicy: SecurityPolicyConfig;
  experienceMode: ExperienceMode;
  systemProxyEnabled: boolean;
  fakeIps: FakeIpEntry[];
  logs: LogEntry[];
  activePaletteDisplayName: string;
  activeAccent: AccentTint;
  language: 'en' | 'fr';
  onUpdateSecurityPolicy: (partial: Partial<SecurityPolicyConfig>) => void;
  onSetInterceptionMode: (mode: InterceptionMode) => void;
  onToggleSystemProxy: () => Promise<void>;
  onOpenThemeForge: () => void;
  onToggleLanguage: (lang: 'en' | 'fr') => void;
  onOpenWizard: () => void;
  onOpenGlossary: () => void;
  onOpenLauncher: () => void;
  onImportProfile: (file: File) => void;
  onExportProfile: () => void;
  onAllocateDns: (domain: string) => void;
  onFlushDns: () => void;
  onClearLogs: () => void;
}

type DiagnosticSubtab = 'overview' | 'dns' | 'logs';

export const SettingsView: React.FC<SettingsViewProps> = ({
  diagnostics,
  securityPolicy,
  experienceMode,
  systemProxyEnabled,
  fakeIps,
  logs,
  activePaletteDisplayName,
  activeAccent,
  language,
  onUpdateSecurityPolicy,
  onSetInterceptionMode,
  onToggleSystemProxy,
  onOpenThemeForge,
  onToggleLanguage,
  onOpenWizard,
  onOpenGlossary,
  onOpenLauncher,
  onImportProfile,
  onExportProfile,
  onAllocateDns,
  onFlushDns,
  onClearLogs
}) => {
  const { t } = useTranslation();
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [diagSubtab, setDiagSubtab] = useState<DiagnosticSubtab>('overview');
  const [showSimpleDiagnostics, setShowSimpleDiagnostics] = useState(false);

  const allShieldsActive =
    securityPolicy.killSwitchEnabled &&
    securityPolicy.blockUdpOnTcpOnlyProxy &&
    securityPolicy.strictDnsNoLocalFallback &&
    Boolean(securityPolicy.blockQuicUdp443 ?? true) &&
    Boolean(securityPolicy.blockEncryptedDnsBypass ?? true);

  const handleToggleAllShields = () => {
    const next = !allShieldsActive;
    onUpdateSecurityPolicy({
      killSwitchEnabled: next,
      blockUdpOnTcpOnlyProxy: next,
      strictDnsNoLocalFallback: next,
      blockQuicUdp443: next,
      blockEncryptedDnsBypass: next
    });
  };

  return (
    <div className="space-y-6">
      <div className="tf-card p-5">
        <h2 className="text-base font-bold text-tf-primary">
          {t('settings.header.title')}
        </h2>
        <p className="mt-1 text-xs text-tf-secondary">
          {t('settings.header.subtitle')}
        </p>
      </div>

      {/* 1. General & Appearance */}
      <div className="tf-card space-y-4 p-5">
        <div className="flex items-center gap-2">
          <Palette className="h-4 w-4 text-tf-accent" />
          <h3 className="text-sm font-bold text-tf-primary">
            {t('settings.general.title')}
          </h3>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {/* Display Language */}
          <div className="tf-surface-alt flex items-center justify-between p-4">
            <div className="flex items-center gap-3">
              <Languages className="h-4 w-4 text-tf-cyan" />
              <span className="text-xs font-semibold text-tf-primary">
                {t('settings.general.language_label')}
              </span>
            </div>
            <div className="flex items-center gap-1 rounded-tf-md border border-tf-border bg-tf-bg p-0.5">
              <button
                type="button"
                aria-pressed={language === 'fr'}
                onClick={() => onToggleLanguage('fr')}
                className={`rounded-tf-sm px-2.5 py-1 text-xs font-bold transition ${
                  language === 'fr'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'text-tf-secondary hover:text-tf-primary'
                }`}
              >
                {t('app.header.language.fr')}
              </button>
              <button
                type="button"
                aria-pressed={language === 'en'}
                onClick={() => onToggleLanguage('en')}
                className={`rounded-tf-sm px-2.5 py-1 text-xs font-bold transition ${
                  language === 'en'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'text-tf-secondary hover:text-tf-primary'
                }`}
              >
                {t('app.header.language.en')}
              </button>
            </div>
          </div>

          {/* ThemeForge Appearance */}
          <div className="tf-surface-alt flex items-center justify-between p-4">
            <div>
              <div className="text-xs font-semibold text-tf-primary">
                {t('settings.general.theme_label')}
              </div>
              <div className="mt-0.5 text-[11px] text-tf-secondary">
                {activePaletteDisplayName} ({activeAccent})
              </div>
            </div>
            <button
              type="button"
              onClick={onOpenThemeForge}
              className="tf-btn-primary flex items-center gap-1.5 text-xs"
            >
              <Palette className="h-3.5 w-3.5" />
              <span>{t('settings.general.theme_open')}</span>
            </button>
          </div>
        </div>

        {/* Guided Help */}
        <div className="tf-surface-alt flex flex-wrap items-center justify-between gap-3 p-4">
          <div>
            <div className="text-xs font-semibold text-tf-primary">
              {t('settings.general.help_title')}
            </div>
            <div className="mt-0.5 text-[11px] text-tf-secondary">
              {t('settings.general.help_desc')}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onOpenWizard}
              className="tf-surface flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-accent hover:border-tf-accent"
            >
              <Wand2 className="h-3.5 w-3.5" />
              <span>{t('app.help.wizard_button')}</span>
            </button>
            <button
              type="button"
              onClick={onOpenGlossary}
              className="tf-surface flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-secondary hover:border-tf-accent hover:text-tf-primary"
            >
              <BookOpen className="h-3.5 w-3.5 text-tf-accent" />
              <span>{t('app.help.glossary_button')}</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Leak Protection */}
      <div className="tf-card space-y-4 p-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-tf-green" />
          <h3 className="text-sm font-bold text-tf-primary">
            {t('settings.security.title')}
          </h3>
        </div>

        {experienceMode === 'simple' ? (
          <div className="tf-surface-alt flex flex-wrap items-center justify-between gap-4 p-4">
            <div className="flex items-start gap-3">
              {allShieldsActive ? (
                <ShieldCheck className="mt-0.5 h-5 w-5 text-tf-green" />
              ) : (
                <ShieldAlert className="mt-0.5 h-5 w-5 text-tf-orange" />
              )}
              <div>
                <div className="flex items-center gap-2 text-xs font-bold text-tf-primary">
                  <span>{t('settings.security.simple_shield_title')}</span>
                  <span
                    className={`rounded-tf-sm px-2 py-0.5 text-[10px] font-semibold ${
                      allShieldsActive
                        ? 'bg-tf-green/20 text-tf-green'
                        : 'bg-tf-orange/20 text-tf-orange'
                    }`}
                  >
                    {allShieldsActive
                      ? t('settings.security.simple_shield_on')
                      : t('settings.security.simple_shield_off')}
                  </span>
                </div>
                <div className="mt-1 text-[11px] text-tf-secondary">
                  {t('settings.security.simple_shield_desc')}
                </div>
              </div>
            </div>
            <input
              type="checkbox"
              aria-label={t('settings.security.simple_shield_title')}
              checked={allShieldsActive}
              onChange={handleToggleAllShields}
              className="h-4 w-4 cursor-pointer accent-tf-accent"
            />
          </div>
        ) : (
          <div className="space-y-2.5">
            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <ShieldAlert className="mt-0.5 h-4 w-4 text-tf-orange" />
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-bold text-tf-primary">
                    {t('dashboard.security_shield.panel.killswitch_title')}
                    <HelpTooltip text={t('dashboard.tooltips.killswitch')} />
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('dashboard.security_shield.panel.killswitch_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('dashboard.security_shield.panel.killswitch_aria')}
                checked={securityPolicy.killSwitchEnabled}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    killSwitchEnabled: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>

            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <Shield className="mt-0.5 h-4 w-4 text-tf-cyan" />
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-bold text-tf-primary">
                    {t('dashboard.security_shield.panel.udp_guard_title')}
                    <HelpTooltip text={t('dashboard.tooltips.udp_guard')} />
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('dashboard.security_shield.panel.udp_guard_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('dashboard.security_shield.panel.udp_guard_aria')}
                checked={securityPolicy.blockUdpOnTcpOnlyProxy}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    blockUdpOnTcpOnlyProxy: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>

            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <Globe className="mt-0.5 h-4 w-4 text-tf-green" />
                <div>
                  <div className="flex items-center gap-1.5 text-xs font-bold text-tf-primary">
                    {t('dashboard.security_shield.panel.dns_guard_title')}
                    <HelpTooltip text={t('dashboard.tooltips.dns_guard')} />
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('dashboard.security_shield.panel.dns_guard_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('dashboard.security_shield.panel.dns_guard_aria')}
                checked={securityPolicy.strictDnsNoLocalFallback}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    strictDnsNoLocalFallback: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>

            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <Shield className="mt-0.5 h-4 w-4 text-tf-purple" />
                <div>
                  <div className="text-xs font-bold text-tf-primary">
                    {t('settings.security.block_quic_title')}
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('settings.security.block_quic_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('settings.security.block_quic_title')}
                checked={Boolean(securityPolicy.blockQuicUdp443 ?? true)}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    blockQuicUdp443: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>

            <div className="tf-surface-alt flex items-center justify-between p-3">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-4 w-4 text-tf-accent" />
                <div>
                  <div className="text-xs font-bold text-tf-primary">
                    {t('settings.security.block_dot_title')}
                  </div>
                  <div className="text-[11px] text-tf-secondary">
                    {t('settings.security.block_dot_desc')}
                  </div>
                </div>
              </div>
              <input
                type="checkbox"
                aria-label={t('settings.security.block_dot_title')}
                checked={Boolean(securityPolicy.blockEncryptedDnsBypass ?? true)}
                onChange={(e) =>
                  onUpdateSecurityPolicy({
                    blockEncryptedDnsBypass: e.target.checked
                  })
                }
                className="h-4 w-4 cursor-pointer accent-tf-accent"
              />
            </div>
          </div>
        )}
      </div>

      {/* 3. System Integration & Profile Backup */}
      <div className="tf-card space-y-4 p-5">
        <div>
          <div className="flex items-center gap-2">
            <HardDrive className="h-4 w-4 text-tf-cyan" />
            <h3 className="text-sm font-bold text-tf-primary">
              {t('settings.system.title')}
            </h3>
          </div>
          <p className="mt-0.5 text-xs text-tf-secondary">
            {t('settings.system.subtitle')}
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {/* Windows System Proxy */}
          <div className="tf-surface-alt flex items-center justify-between p-4">
            <div>
              <div className="text-xs font-semibold text-tf-primary">
                {t('settings.system.system_proxy_label')}
              </div>
              <div className="mt-0.5 text-[11px] text-tf-secondary">
                {t('app.system_proxy.tooltip')}
              </div>
            </div>
            <button
              type="button"
              aria-pressed={systemProxyEnabled}
              onClick={onToggleSystemProxy}
              className={`rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                systemProxyEnabled
                  ? 'border border-tf-cyan bg-tf-cyan/20 text-tf-cyan'
                  : 'tf-surface text-tf-secondary hover:text-tf-primary'
              }`}
            >
              {systemProxyEnabled
                ? t('app.system_proxy.active')
                : t('app.system_proxy.inactive')}
            </button>
          </div>

          {/* Process Launcher */}
          <div className="tf-surface-alt flex items-center justify-between p-4">
            <div>
              <div className="text-xs font-semibold text-tf-primary">
                {t('settings.system.launcher_title')}
              </div>
              <div className="mt-0.5 text-[11px] text-tf-secondary">
                {t('settings.system.launcher_desc')}
              </div>
            </div>
            <button
              type="button"
              onClick={onOpenLauncher}
              className="tf-surface flex items-center gap-1.5 border-tf-cyan/50 px-3 py-1.5 text-xs font-semibold text-tf-cyan hover:border-tf-cyan"
            >
              <Rocket className="h-3.5 w-3.5" />
              <span>{t('app.launcher.button')}</span>
            </button>
          </div>
        </div>

        {/* Expert-only Interception Mode + Profile Backup */}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {experienceMode === 'expert' && (
            <div className="tf-surface-alt flex items-center justify-between p-4">
              <label
                htmlFor="settings-interception-mode"
                className="text-xs font-semibold text-tf-primary"
              >
                {t('settings.system.interception_mode_label')}
              </label>
              <select
                id="settings-interception-mode"
                value={diagnostics.interceptionMode}
                onChange={(e) =>
                  onSetInterceptionMode(e.target.value as InterceptionMode)
                }
                className="rounded-tf-md border border-tf-border bg-tf-surface px-2.5 py-1.5 text-xs text-tf-primary focus:border-tf-accent focus:outline-none"
              >
                <option value="hybrid">{t('app.header.mode.hybrid')}</option>
                <option value="driver">{t('app.header.mode.driver')}</option>
                <option value="relay">{t('app.header.mode.relay')}</option>
              </select>
            </div>
          )}

          <div
            className={`tf-surface-alt flex flex-wrap items-center justify-between gap-3 p-4 ${
              experienceMode !== 'expert' ? 'md:col-span-2' : ''
            }`}
          >
            <div>
              <div className="text-xs font-semibold text-tf-primary">
                {t('settings.system.profile_title')}
              </div>
              <div className="mt-0.5 text-[11px] text-tf-secondary">
                {t('settings.system.profile_desc')}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept="application/json,.json"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    onImportProfile(file);
                  }
                  e.target.value = '';
                }}
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="tf-surface flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-primary hover:border-tf-accent"
              >
                <Upload className="h-3.5 w-3.5" />
                <span>{t('app.header.profile.import')}</span>
              </button>
              <button
                type="button"
                onClick={onExportProfile}
                className="tf-surface flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-tf-primary hover:border-tf-accent"
              >
                <Download className="h-3.5 w-3.5" />
                <span>{t('app.header.profile.export')}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Technical Diagnostics (Overview + Fake-IP DNS + Event Logs) */}
      <div className="tf-card space-y-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-tf-purple" />
            <h3 className="text-sm font-bold text-tf-primary">
              {t('settings.diagnostics.title')}
            </h3>
          </div>
          {experienceMode === 'simple' && (
            <button
              type="button"
              aria-expanded={showSimpleDiagnostics}
              onClick={() => setShowSimpleDiagnostics((prev) => !prev)}
              className="tf-surface-alt px-3 py-1 text-xs font-semibold text-tf-secondary hover:border-tf-accent hover:text-tf-primary"
            >
              {showSimpleDiagnostics
                ? t('settings.diagnostics.hide_title')
                : t('settings.diagnostics.title')}
            </button>
          )}
        </div>

        {(experienceMode === 'expert' || showSimpleDiagnostics) && (
          <>
            <div className="flex flex-wrap gap-2 border-b border-tf-border pb-2">
              <button
                type="button"
                aria-pressed={diagSubtab === 'overview'}
                onClick={() => setDiagSubtab('overview')}
                className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                  diagSubtab === 'overview'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                }`}
              >
                <Activity className="h-3.5 w-3.5" />
                <span>{t('settings.diagnostics.subtab_overview')}</span>
              </button>
              <button
                type="button"
                aria-pressed={diagSubtab === 'dns'}
                onClick={() => setDiagSubtab('dns')}
                className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                  diagSubtab === 'dns'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                }`}
              >
                <Globe className="h-3.5 w-3.5" />
                <span>
                  {t('settings.diagnostics.subtab_dns')} ({fakeIps.length})
                </span>
              </button>
              <button
                type="button"
                aria-pressed={diagSubtab === 'logs'}
                onClick={() => setDiagSubtab('logs')}
                className={`flex items-center gap-1.5 rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
                  diagSubtab === 'logs'
                    ? 'bg-tf-accent text-tf-bg'
                    : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
                }`}
              >
                <FileText className="h-3.5 w-3.5" />
                <span>
                  {t('settings.diagnostics.subtab_logs')} ({logs.length})
                </span>
              </button>
            </div>

            {diagSubtab === 'overview' && (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="tf-surface-alt p-3">
                  <div className="text-[11px] uppercase text-tf-secondary">
                    {t('dashboard.system.status.os_label')}
                  </div>
                  <div className="mt-1 font-mono text-sm font-bold text-tf-primary">
                    {diagnostics.osName}
                  </div>
                </div>
                <div className="tf-surface-alt p-3">
                  <div className="text-[11px] uppercase text-tf-secondary">
                    {t('dashboard.system.status.relay_tcp_label')}
                  </div>
                  <div className="mt-1 flex items-center gap-1.5 font-mono text-sm font-bold text-tf-cyan">
                    <Server className="h-3.5 w-3.5" />
                    {diagnostics.relayTcpEndpoint}
                  </div>
                </div>
                <div className="tf-surface-alt p-3">
                  <div className="text-[11px] uppercase text-tf-secondary">
                    {t('dashboard.system.status.relay_http_label')}
                  </div>
                  <div className="mt-1 font-mono text-sm font-bold text-tf-orange">
                    {diagnostics.relayHttpEndpoint}
                  </div>
                </div>
                <div className="tf-surface-alt p-3">
                  <div className="text-[11px] uppercase text-tf-secondary">
                    {t('dashboard.system.status.dns_server_label')}
                  </div>
                  <div className="mt-1 font-mono text-sm font-bold text-tf-green">
                    {diagnostics.dnsEndpoint}
                  </div>
                </div>
              </div>
            )}

            {diagSubtab === 'dns' && (
              <DnsView
                entries={fakeIps}
                onAllocate={onAllocateDns}
                onFlush={onFlushDns}
              />
            )}

            {diagSubtab === 'logs' && (
              <LogsView logs={logs} onClear={onClearLogs} />
            )}
          </>
        )}
      </div>
    </div>
  );
};
