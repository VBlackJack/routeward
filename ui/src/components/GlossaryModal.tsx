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
import { BookOpen, Sparkles, Terminal, X } from 'lucide-react';

interface GlossaryModalProps {
  onClose: () => void;
}

const GLOSSARY_KEYS = [
  'proxy',
  'chain',
  'fake_ip',
  'killswitch',
  'rules',
  'system_proxy'
] as const;

export const GlossaryModal: React.FC<GlossaryModalProps> = ({ onClose }) => {
  const { t } = useTranslation();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="tf-card flex max-h-[85vh] w-full max-w-3xl flex-col overflow-hidden p-6 shadow-2xl">
        <div className="flex items-start justify-between border-b border-tf-border pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-tf-lg bg-tf-accent/20 text-tf-accent">
              <BookOpen className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-tf-primary">
                {t('glossary.modal.title')}
              </h2>
              <p className="text-xs text-tf-secondary">
                {t('glossary.modal.subtitle')}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-tf-sm p-1 text-tf-secondary hover:bg-tf-surface-alt hover:text-tf-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 flex-1 space-y-3 overflow-y-auto pr-1">
          {GLOSSARY_KEYS.map((key) => (
            <div key={key} className="tf-surface-alt space-y-2 p-4">
              <div className="text-xs font-bold text-tf-accent">
                {t(`glossary.items.${key}.term`)}
              </div>
              <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                <div className="rounded-tf-sm border border-tf-green/30 bg-tf-bg/70 p-2.5 text-xs">
                  <div className="mb-1 flex items-center gap-1.5 text-[10px] font-bold uppercase text-tf-green">
                    <Sparkles className="h-3 w-3" />
                    <span>{t('app.experience_mode.simple')}</span>
                  </div>
                  <p className="leading-relaxed text-tf-primary">
                    {t(`glossary.items.${key}.simple`)}
                  </p>
                </div>
                <div className="rounded-tf-sm border border-tf-cyan/30 bg-tf-bg/70 p-2.5 text-xs">
                  <div className="mb-1 flex items-center gap-1.5 font-mono text-[10px] font-bold uppercase text-tf-cyan">
                    <Terminal className="h-3 w-3" />
                    <span>{t('app.experience_mode.expert')}</span>
                  </div>
                  <p className="font-mono text-[11px] leading-relaxed text-tf-secondary">
                    {t(`glossary.items.${key}.expert`)}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 flex justify-end border-t border-tf-border pt-3">
          <button
            onClick={onClose}
            className="tf-btn-accent px-5 py-2 text-xs font-bold"
          >
            {t('glossary.modal.close')}
          </button>
        </div>
      </div>
    </div>
  );
};
