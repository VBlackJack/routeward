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
import { FileDown, ShieldAlert } from 'lucide-react';
import { UI_CONFIG } from '../config/constants';
import {
  buildDiagnosticFileName,
  readManifestSections
} from '../services/diagnosticBundle';
import { formatBytes } from '../services/format';
import {
  CollectDiagnosticsRequest,
  DiagnosticBundle
} from '../types/routeward';
import { ModalContainer } from './ModalContainer';

interface DiagnosticExportModalProps {
  onCollect: (req: CollectDiagnosticsRequest) => Promise<DiagnosticBundle>;
  onClose: () => void;
  /** Called with the file name once the download was started. */
  onDownloaded?: (fileName: string) => void;
}

/** Readable names of the sections the daemon is known to send; other names are shown as is. */
const SECTION_LABEL_KEYS: Record<string, string> = {
  system: 'diagnostics.export.section.system',
  profile: 'diagnostics.export.section.profile',
  connections: 'diagnostics.export.section.connections',
  blocked: 'diagnostics.export.section.blocked',
  logs: 'diagnostics.export.section.logs'
};

const REDACTION_KEY_PREFIX = 'diagnostics.export.redaction.';

/** Builds the redacted diagnostic file in two steps: choose what goes in, check it, then download. */
export const DiagnosticExportModal: React.FC<DiagnosticExportModalProps> = ({
  onCollect,
  onClose,
  onDownloaded
}) => {
  const { t, i18n } = useTranslation();
  const titleId = useId();
  // The daemon sends stable codes; a code this version does not know is shown as it is.
  const redactionLabel = (code: string): string => {
    const key = `${REDACTION_KEY_PREFIX}${code}`;
    return i18n.exists(key) ? t(key) : code;
  };
  const [logDays, setLogDays] = useState<number>(UI_CONFIG.DIAGNOSTIC_LOG_DAYS_DEFAULT);
  const [includeConnections, setIncludeConnections] = useState(true);
  const [includeProfile, setIncludeProfile] = useState(true);
  const [maskDomains, setMaskDomains] = useState(false);
  const [bundle, setBundle] = useState<DiagnosticBundle | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  const changeOption = (apply: () => void) => {
    apply();
    setBundle(null);
    setFailed(false);
  };

  const prepare = () => {
    setBusy(true);
    setFailed(false);
    onCollect({ logDays, includeConnections, includeProfile, maskDomains })
      .then((result) => setBundle(result))
      .catch(() => setFailed(true))
      .finally(() => setBusy(false));
  };

  const download = () => {
    if (!bundle) return;
    const fileName = buildDiagnosticFileName(new Date());
    const blob = new Blob([JSON.stringify(bundle, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
    onDownloaded?.(fileName);
  };

  const sections = bundle ? readManifestSections(bundle) : [];
  const totalBytes = sections.reduce((sum, s) => sum + s.bytes, 0);
  const redactions = bundle?.manifest.redactions ?? [];

  return (
    <ModalContainer
      onClose={onClose}
      labelledBy={titleId}
      backdropClassName="bg-black/75 p-4 backdrop-blur-sm"
    >
      <div className="tf-card w-full max-w-lg space-y-4 p-6 shadow-2xl">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-tf-lg bg-tf-accent/20 text-tf-accent">
            <FileDown className="h-5 w-5" />
          </div>
          <div>
            <h2 id={titleId} className="text-base font-bold text-tf-primary">
              {t('diagnostics.export.title')}
            </h2>
            <p className="mt-1 text-xs text-tf-secondary">{t('diagnostics.export.intro')}</p>
          </div>
        </div>

        <fieldset className="space-y-2 text-xs text-tf-primary">
          <legend className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-tf-secondary">
            {t('diagnostics.export.options')}
          </legend>
          <label className="flex items-center gap-2">
            <span>{t('diagnostics.export.log_days')}</span>
            <select
              name="export-log-days"
              value={logDays}
              onChange={(e) => changeOption(() => setLogDays(Number(e.target.value)))}
              className="tf-input px-2 py-1 text-xs"
            >
              {UI_CONFIG.DIAGNOSTIC_LOG_DAYS_OPTIONS.map((days) => (
                <option key={days} value={days}>
                  {t('diagnostics.export.days', { count: days })}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              name="export-include-connections"
              checked={includeConnections}
              onChange={(e) =>
                changeOption(() => setIncludeConnections(e.target.checked))
              }
            />
            {t('diagnostics.export.include_connections')}
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              name="export-include-profile"
              checked={includeProfile}
              onChange={(e) => changeOption(() => setIncludeProfile(e.target.checked))}
            />
            {t('diagnostics.export.include_profile')}
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              name="export-mask-sites"
              checked={maskDomains}
              onChange={(e) => changeOption(() => setMaskDomains(e.target.checked))}
            />
            {t('diagnostics.export.mask_sites')}
          </label>
        </fieldset>

        {!maskDomains && (
          <p
            role="note"
            className="flex items-start gap-2 rounded-tf-md border border-tf-orange/40 bg-tf-orange/10 p-2.5 text-[11px] text-tf-primary"
          >
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-tf-orange" />
            {t('diagnostics.export.sites_warning')}
          </p>
        )}

        {failed && (
          <p role="alert" className="text-xs text-tf-red">
            {t('diagnostics.export.error')}
          </p>
        )}

        {bundle && (
          <div className="space-y-2 text-xs">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-tf-secondary">
              {t('diagnostics.export.manifest_title')}
            </h3>
            <table className="w-full text-left">
              <caption className="sr-only">{t('diagnostics.export.manifest_title')}</caption>
              <thead className="text-[11px] text-tf-secondary">
                <tr>
                  <th className="py-1 pr-2">{t('diagnostics.export.col_section')}</th>
                  <th className="py-1 text-right">{t('diagnostics.export.col_size')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-tf-border text-tf-primary">
                {sections.map((section) => (
                  <tr key={section.name}>
                    <td className="py-1 pr-2">
                      {SECTION_LABEL_KEYS[section.name]
                        ? t(SECTION_LABEL_KEYS[section.name])
                        : section.name}
                    </td>
                    <td className="py-1 text-right font-mono">{formatBytes(section.bytes)}</td>
                  </tr>
                ))}
              </tbody>
              <tfoot className="font-semibold text-tf-primary">
                <tr>
                  <td className="pt-1">{t('diagnostics.export.total')}</td>
                  <td className="pt-1 text-right font-mono">{formatBytes(totalBytes)}</td>
                </tr>
              </tfoot>
            </table>
            {redactions.length > 0 && (
              <p className="text-[11px] text-tf-secondary">
                {t('diagnostics.export.redactions', {
                  list: redactions.map(redactionLabel).join(', ')
                })}
              </p>
            )}
            <p className="text-[11px] text-tf-secondary">
              {t('diagnostics.export.never_sent')}
            </p>
          </div>
        )}

        <div className="flex justify-end gap-2 border-t border-tf-border pt-4">
          <button
            type="button"
            onClick={onClose}
            className="tf-surface-alt px-4 py-2 text-xs font-semibold text-tf-secondary hover:text-tf-primary"
          >
            {t('diagnostics.export.close')}
          </button>
          {bundle ? (
            <button
              type="button"
              onClick={download}
              className="tf-btn-accent px-5 py-2 text-xs font-bold"
            >
              {t('diagnostics.export.download')}
            </button>
          ) : (
            <button
              type="button"
              onClick={prepare}
              disabled={busy}
              className="tf-btn-accent px-5 py-2 text-xs font-bold"
            >
              {busy ? t('diagnostics.export.preparing') : t('diagnostics.export.prepare')}
            </button>
          )}
        </div>
      </div>
    </ModalContainer>
  );
};
