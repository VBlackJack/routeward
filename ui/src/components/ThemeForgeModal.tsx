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

import React, { useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Check, Palette, Upload, X } from 'lucide-react';
import { useThemeForge } from '../theme/ThemeForgeContext';
import { AccentTint, ThemeFamily } from '../types/routeward';
import { ModalContainer } from './ModalContainer';

interface ThemeForgeModalProps {
  onClose: () => void;
}

const FAMILIES: ThemeFamily[] = ['Root', 'Dark', 'Light', 'Alt'];

export const ThemeForgeModal: React.FC<ThemeForgeModalProps> = ({ onClose }) => {
  const { t } = useTranslation();
  const titleId = useId();
  const [importError, setImportError] = useState(false);
  const {
    palettes,
    accents,
    activeThemeName,
    activeAccent,
    activePalette,
    effectiveColors,
    setTheme,
    setAccent,
    importExternalPalette
  } = useThemeForge();

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setImportError(false);
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        const imported = importExternalPalette(reader.result);
        setImportError(!imported);
      }
    };
    reader.onerror = () => {
      setImportError(true);
    };
    reader.readAsText(file);
  };

  const getAccentSwatchColor = (accent: AccentTint): string => {
    if (accent === 'Default') {
      return activePalette.colors.Accent;
    }
    return activePalette.colors[accent];
  };

  return (
    <ModalContainer onClose={onClose} labelledBy={titleId}>
      <div className="tf-card flex max-h-[88vh] w-full max-w-4xl flex-col overflow-hidden shadow-2xl">
        <div className="flex items-center justify-between border-b border-tf-border px-6 py-4">
          <div className="flex items-center gap-3">
            <Palette className="h-5 w-5 text-tf-accent" />
            <div>
              <h2 id={titleId} className="text-lg font-bold text-tf-primary">
                {t('themeforge.modal.title')}
              </h2>
              <p className="text-xs text-tf-secondary">
                {t('themeforge.modal.subtitle')}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('themeforge.modal.close')}
            className="rounded p-1.5 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto p-6">
          {importError && (
            <div
              role="alert"
              className="flex items-center gap-2 rounded-tf-md border border-tf-red/40 bg-tf-red/10 px-3 py-2 text-xs text-tf-red"
            >
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{t('themeforge.modal.import_error')}</span>
            </div>
          )}
          {/* Accent Tint Selector */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-tf-secondary">
                {t('themeforge.modal.accent_label')}
              </span>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="tf-surface-alt flex items-center gap-1.5 px-3 py-1 text-xs font-medium text-tf-primary hover:border-tf-accent"
              >
                <Upload className="h-3.5 w-3.5 text-tf-accent" />
                {t('themeforge.modal.import_palette')}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                className="hidden"
                onChange={handleFileChange}
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {accents.map((accent) => {
                const selected = activeAccent === accent;
                const swatchHex = getAccentSwatchColor(accent);
                return (
                  <button
                    key={accent}
                    onClick={() => setAccent(accent)}
                    className={`flex items-center gap-2 rounded-tf-md border px-3 py-1.5 text-xs font-medium transition ${
                      selected
                        ? 'border-tf-accent bg-tf-surface-alt text-tf-primary'
                        : 'border-tf-border bg-tf-bg text-tf-secondary hover:text-tf-primary'
                    }`}
                  >
                    <span
                      className="h-3.5 w-3.5 rounded-full border border-black/20"
                      style={{ backgroundColor: swatchHex }}
                    />
                    <span>{t(`themeforge.accents.${accent}`)}</span>
                    {selected && <Check className="h-3.5 w-3.5 text-tf-accent" />}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Palettes by Family */}
          {FAMILIES.map((family) => {
            const familyPalettes = palettes.filter((p) => p.family === family);
            return (
              <div key={family} className="space-y-2.5">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-tf-secondary">
                  {t(`themeforge.families.${family}`)}
                </h3>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4">
                  {familyPalettes.map((pal) => {
                    const isSelected = pal.name === activeThemeName;
                    return (
                      <button
                        key={pal.name}
                        onClick={() => setTheme(pal.name)}
                        className={`flex flex-col justify-between rounded-tf-lg border p-3 text-left transition ${
                          isSelected
                            ? 'border-2 border-tf-accent shadow-md'
                            : 'border-tf-border hover:border-tf-comment'
                        }`}
                        style={{
                          backgroundColor: pal.colors.Background,
                          color: pal.colors.Foreground
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-bold">
                            {pal.displayName}
                          </span>
                          {isSelected && (
                            <Check
                              className="h-4 w-4"
                              style={{ color: pal.colors.Accent }}
                            />
                          )}
                        </div>
                        <span
                          className="mt-0.5 text-[11px]"
                          style={{ color: pal.colors.Comment }}
                        >
                          {pal.colors.Background}
                        </span>
                        <div className="mt-3 flex gap-1.5">
                          {[
                            pal.colors.CurrentLine,
                            pal.colors.Accent,
                            pal.colors.Cyan,
                            pal.colors.Green,
                            pal.colors.Orange,
                            pal.colors.Pink
                          ].map((hex, i) => (
                            <span
                              key={i}
                              className="h-3 flex-1 rounded-tf-xs"
                              style={{ backgroundColor: hex }}
                            />
                          ))}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}

          {/* Semantic Preview Strip */}
          <div className="tf-surface-alt p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-tf-secondary">
                {t('themeforge.modal.preview_label')} - {activePalette.displayName}
              </span>
              <span className="text-[11px] text-tf-secondary">
                {activePalette.attribution}
              </span>
            </div>
            <div className="grid grid-cols-4 gap-2 sm:grid-cols-8">
              {(
                [
                  'Background',
                  'CurrentLine',
                  'Foreground',
                  'Comment',
                  'Accent',
                  'Success',
                  'Warning',
                  'Error'
                ] as const
              ).map((slot) => (
                <div
                  key={slot}
                  className="flex flex-col items-center rounded border border-tf-border bg-tf-bg p-2"
                >
                  <div
                    className="h-5 w-full rounded-tf-xs border border-tf-border"
                    style={{ backgroundColor: effectiveColors[slot] }}
                  />
                  <span className="mt-1 text-[10px] font-semibold text-tf-primary">
                    {slot}
                  </span>
                  <span className="font-mono text-[10px] text-tf-secondary">
                    {effectiveColors[slot]}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex justify-end border-t border-tf-border px-6 py-3">
          <button
            type="button"
            onClick={onClose}
            className="tf-btn-accent px-5 py-1.5 text-sm"
          >
            {t('themeforge.modal.close')}
          </button>
        </div>
      </div>
    </ModalContainer>
  );
};
