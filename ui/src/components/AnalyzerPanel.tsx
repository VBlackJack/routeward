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

import React from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, CheckCircle, Info, Stethoscope } from 'lucide-react';
import { formatLogTime } from '../services/format';
import {
  FixAction,
  Finding,
  FindingSeverity,
  ProxyNode,
  RoutingRule
} from '../types/routeward';

interface AnalyzerPanelProps {
  findings: Finding[];
  proxies: ProxyNode[];
  rules: RoutingRule[];
  loading?: boolean;
  error?: boolean;
  /** True once an analysis has completed (so "nothing found" is not shown before the first run). */
  analyzed?: boolean;
  onRun: () => void;
  onFix: (fix: FixAction) => void;
  onExport?: () => void;
}

/** Label of the button of each fix that can be run from the panel. */
const FIX_BUTTON_KEYS: Partial<Record<FixAction['type'], string>> = {
  openProxy: 'analyzer.action.open_proxy',
  testProxy: 'analyzer.action.test_proxy',
  unblock: 'analyzer.action.unblock',
  editRule: 'analyzer.action.edit_rule',
  pauseProtection: 'analyzer.action.pause',
  openSetting: 'analyzer.action.open_setting'
};

/** Texts of a finding whose code this version does not know (a newer daemon). */
const UNKNOWN_FINDING_KEYS = {
  title: 'analyzer.unknown.title',
  body: 'analyzer.unknown.body',
  fix: 'analyzer.unknown.fix'
} as const;

const SEVERITY_CLASSES: Record<FindingSeverity, string> = {
  critical: 'border-l-tf-red',
  warning: 'border-l-tf-orange',
  info: 'border-l-tf-cyan'
};

/** Findings of the analyzer in plain words, each with the fix button it makes possible. */
export const AnalyzerPanel: React.FC<AnalyzerPanelProps> = ({
  findings,
  proxies,
  rules,
  loading = false,
  error = false,
  analyzed = false,
  onRun,
  onFix,
  onExport
}) => {
  const { t, i18n } = useTranslation();

  const textFor = (finding: Finding, part: 'title' | 'body' | 'fix'): string => {
    const key = `analyzer.findings.${finding.code}.${part}`;
    const proxyId = finding.subject.proxyId;
    const ruleId = finding.subject.ruleId;
    const params = {
      app: finding.subject.app ?? '',
      site: finding.subject.site ?? '',
      proxy: proxyId ? (proxies.find((p) => p.id === proxyId)?.name ?? proxyId) : '',
      rule: ruleId ? (rules.find((r) => r.id === ruleId)?.name ?? ruleId) : '',
      count: finding.evidenceCount
    };
    if (i18n.exists(key)) {
      return t(key, params);
    }
    return t(UNKNOWN_FINDING_KEYS[part], params);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-bold text-tf-primary">
            <Stethoscope className="h-4 w-4 text-tf-cyan" />
            {t('analyzer.title')}
          </h3>
          <p className="mt-1 text-xs text-tf-secondary">{t('analyzer.subtitle')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onRun}
            disabled={loading}
            className="tf-btn-accent px-4 py-2 text-xs font-bold"
          >
            {loading ? t('analyzer.running') : t('analyzer.run')}
          </button>
          {onExport && (
            <button
              type="button"
              onClick={onExport}
              className="tf-surface-alt px-4 py-2 text-xs font-semibold text-tf-primary hover:border-tf-accent"
            >
              {t('analyzer.export')}
            </button>
          )}
        </div>
      </div>

      {error && (
        <p role="alert" className="text-xs text-tf-red">
          {t('analyzer.error')}
        </p>
      )}

      {analyzed && !error && findings.length === 0 && (
        <p className="flex items-center gap-2 text-xs text-tf-green">
          <CheckCircle className="h-4 w-4" />
          {t('analyzer.none')}
        </p>
      )}

      <ul className="space-y-3">
        {findings.map((finding, index) => {
          const buttonKey = FIX_BUTTON_KEYS[finding.fix.type];
          return (
            <li
              key={`${finding.code}-${index}`}
              className={`tf-card space-y-2 border-l-4 p-4 ${SEVERITY_CLASSES[finding.severity]}`}
            >
              <div className="flex items-start gap-2">
                {finding.severity === 'info' ? (
                  <Info className="mt-0.5 h-4 w-4 shrink-0 text-tf-cyan" />
                ) : (
                  <AlertTriangle
                    className={`mt-0.5 h-4 w-4 shrink-0 ${
                      finding.severity === 'critical' ? 'text-tf-red' : 'text-tf-orange'
                    }`}
                  />
                )}
                <div className="space-y-1">
                  <h4 className="text-sm font-semibold text-tf-primary">
                    {textFor(finding, 'title')}
                  </h4>
                  <p className="text-xs text-tf-secondary">{textFor(finding, 'body')}</p>
                  <p className="text-xs text-tf-primary">{textFor(finding, 'fix')}</p>
                  <p className="text-[11px] text-tf-secondary">
                    {t('analyzer.evidence', { count: finding.evidenceCount })}
                    {finding.lastSeen
                      ? ` - ${t('analyzer.last_seen', { time: formatLogTime(finding.lastSeen) })}`
                      : ''}
                  </p>
                </div>
              </div>
              {buttonKey && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={() => onFix(finding.fix)}
                    className="tf-surface-alt px-3 py-1.5 text-xs font-semibold text-tf-accent hover:border-tf-accent"
                  >
                    {t(buttonKey)}
                  </button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
};
