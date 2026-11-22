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

import React, { useId, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { CheckCircle2, Globe, LifeBuoy, ShieldAlert, X } from 'lucide-react';
import { getFriendlyAppName, getHumanErrorKey } from '../services/friendly';
import {
  formatPauseEnd,
  ProtectionHealth
} from '../services/protectionHealth';
import { TrackedConnection } from '../types/routeward';
import { UI_CONFIG } from '../config/constants';
import { ModalContainer } from './ModalContainer';

interface TroubleshootModalProps {
  connections: TrackedConnection[];
  /** Shared protection state, used to explain an empty list (paused, stopped). */
  health?: ProtectionHealth;
  /** Tests the proxy that is currently in use. */
  onTestProxy?: () => void;
  /** Pauses protection for the given number of minutes. */
  onPauseProtection?: (minutes: number) => void;
  /** Opens the proxy screen. */
  onChangeProxy?: () => void;
  onAllowAppDirect: (conn: TrackedConnection) => void;
  onAllowSiteDirect: (conn: TrackedConnection) => void;
  onClose: () => void;
}

const MAX_RECENT_ISSUES = 8;

/** Reasons that mean "the proxy does not answer" rather than "a rule blocked it". */
const PROXY_DOWN_REASON_KEYS: readonly string[] = [
  'troubleshoot.reasons.killswitch',
  'troubleshoot.reasons.timeout',
  'troubleshoot.reasons.unreachable'
];

export const TroubleshootModal: React.FC<TroubleshootModalProps> = ({
  connections,
  health,
  onTestProxy,
  onPauseProtection,
  onChangeProxy,
  onAllowAppDirect,
  onAllowSiteDirect,
  onClose
}) => {
  const { t, i18n } = useTranslation();
  const titleId = useId();
  // A pause only makes sense while protection is filtering traffic; without a known state, offer it.
  const canPause = health === undefined || health.engineActive;

  const recentIssues = useMemo(() => {
    const seen = new Set<string>();
    const items: TrackedConnection[] = [];
    for (const conn of connections) {
      if (conn.status !== 'blocked' && !conn.errorDetail) {
        continue;
      }
      const target = conn.resolvedDomain || conn.targetHost;
      const key = `${conn.processName.toLowerCase()}::${target.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push(conn);
      if (items.length >= MAX_RECENT_ISSUES) break;
    }
    return items;
  }, [connections]);

  const proxyDownCount = recentIssues.filter((conn) =>
    PROXY_DOWN_REASON_KEYS.includes(getHumanErrorKey(conn.errorDetail))
  ).length;
  const mostlyProxyDown =
    recentIssues.length > 0 && proxyDownCount * 2 > recentIssues.length;

  const emptyMessage =
    health?.state === 'paused' && health.pausedUntilEpochMs !== null
      ? t('troubleshoot.modal.empty_paused', {
          time: formatPauseEnd(health.pausedUntilEpochMs, i18n.language)
        })
      : health?.state === 'service_stopped' || health?.state === 'stopped'
        ? t('troubleshoot.modal.empty_stopped')
        : t('troubleshoot.modal.empty');

  return (
    <ModalContainer
      onClose={onClose}
      labelledBy={titleId}
      backdropClassName="bg-black/75 p-4 backdrop-blur-sm"
    >
      <div className="tf-card flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden p-6 shadow-2xl">
        <div className="flex items-start justify-between border-b border-tf-border pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-tf-lg bg-tf-orange/20 text-tf-orange">
              <LifeBuoy className="h-5 w-5" />
            </div>
            <div>
              <h2 id={titleId} className="text-base font-bold text-tf-primary">
                {t('troubleshoot.modal.title')}
              </h2>
              <p className="text-xs text-tf-secondary">
                {t('troubleshoot.modal.subtitle')}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('troubleshoot.modal.close')}
            className="rounded-tf-sm p-1.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 flex-1 space-y-2.5 overflow-y-auto pr-1">
          {mostlyProxyDown && (
            <div
              role="alert"
              className="space-y-2 rounded-tf-md border border-tf-orange/40 bg-tf-orange/10 p-3.5"
            >
              <div className="text-xs font-bold text-tf-orange">
                {t('troubleshoot.proxy_down.title')}
              </div>
              <p className="text-[11px] text-tf-primary">
                {t('troubleshoot.proxy_down.desc')}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                {onTestProxy && (
                  <button
                    type="button"
                    onClick={onTestProxy}
                    className="tf-btn-accent px-3 py-1.5 text-[11px] font-bold"
                  >
                    {t('troubleshoot.proxy_down.test')}
                  </button>
                )}
                {onPauseProtection && canPause && (
                  <button
                    type="button"
                    onClick={() =>
                      onPauseProtection(UI_CONFIG.OUTAGE_PAUSE_MINUTES)
                    }
                    className="tf-surface px-3 py-1.5 text-[11px] font-semibold text-tf-primary hover:border-tf-orange"
                  >
                    {t('troubleshoot.proxy_down.pause', {
                      minutes: UI_CONFIG.OUTAGE_PAUSE_MINUTES
                    })}
                  </button>
                )}
                {onChangeProxy && (
                  <button
                    type="button"
                    onClick={onChangeProxy}
                    className="tf-surface px-3 py-1.5 text-[11px] font-semibold text-tf-primary hover:border-tf-accent"
                  >
                    {t('troubleshoot.proxy_down.change')}
                  </button>
                )}
              </div>
            </div>
          )}
          {recentIssues.length > 0 && (
            <p className="text-[11px] text-tf-secondary">
              {t('troubleshoot.modal.allow_warning')}
            </p>
          )}
          {recentIssues.length === 0 ? (
            <div className="tf-surface-alt flex flex-col items-center gap-2 p-6 text-center text-xs text-tf-secondary">
              <CheckCircle2 className="h-6 w-6 text-tf-green" />
              <span>{emptyMessage}</span>
            </div>
          ) : (
            recentIssues.map((conn) => {
              const target = conn.resolvedDomain || conn.targetHost;
              const friendly = getFriendlyAppName(conn.processName);
              const reasonKey = getHumanErrorKey(conn.errorDetail);
              return (
                <div
                  key={conn.id}
                  className="tf-surface-alt flex flex-wrap items-center justify-between gap-3 p-3.5"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <ShieldAlert className="h-4 w-4 shrink-0 text-tf-red" />
                      <span className="text-xs font-bold text-tf-primary">
                        {friendly.displayName}
                      </span>
                      {friendly.technicalName && (
                        <span className="rounded bg-tf-surface px-1.5 py-0.5 font-mono text-[10px] text-tf-secondary">
                          {friendly.technicalName}
                        </span>
                      )}
                      <span className="truncate font-mono text-[11px] text-tf-cyan">
                        {target}
                      </span>
                    </div>
                    <p className="text-[11px] text-tf-orange">
                      {t(reasonKey)}
                    </p>
                  </div>
                  <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => onAllowAppDirect(conn)}
                      className="rounded-tf-md bg-tf-green/20 px-2.5 py-1.5 text-[11px] font-bold text-tf-green transition hover:bg-tf-green/30"
                    >
                      {t('troubleshoot.modal.allow_app_direct')}
                    </button>
                    {target && (
                      <button
                        type="button"
                        onClick={() => onAllowSiteDirect(conn)}
                        className="tf-surface flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-semibold text-tf-primary hover:border-tf-green hover:text-tf-green"
                      >
                        <Globe className="h-3 w-3" />
                        {t('troubleshoot.modal.allow_site_direct')}
                      </button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        <div className="mt-4 flex justify-end border-t border-tf-border pt-3">
          <button
            type="button"
            onClick={onClose}
            className="tf-btn-accent px-5 py-2 text-xs font-bold"
          >
            {t('troubleshoot.modal.close')}
          </button>
        </div>
      </div>
    </ModalContainer>
  );
};
