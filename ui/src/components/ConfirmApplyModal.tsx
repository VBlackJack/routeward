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

import React, { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import { ModalContainer } from './ModalContainer';

interface ConfirmApplyModalProps {
  title: string;
  intro: string;
  /** One plain-language line per change that will be made. */
  changes: string[];
  onConfirm: () => void;
  onCancel: () => void;
}

/** Asks for a go-ahead before several protection settings change at once. */
export const ConfirmApplyModal: React.FC<ConfirmApplyModalProps> = ({
  title,
  intro,
  changes,
  onConfirm,
  onCancel
}) => {
  const { t } = useTranslation();
  const titleId = useId();

  return (
    <ModalContainer
      onClose={onCancel}
      labelledBy={titleId}
      backdropClassName="bg-black/75 p-4 backdrop-blur-sm"
    >
      <div className="tf-card w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-tf-lg bg-tf-accent/20 text-tf-accent">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h2 id={titleId} className="text-base font-bold text-tf-primary">
              {title}
            </h2>
            <p className="mt-1 text-xs text-tf-secondary">{intro}</p>
          </div>
        </div>
        {changes.length > 0 && (
          <ul className="mt-4 list-disc space-y-1 pl-5 text-xs text-tf-primary">
            {changes.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
        <p className="mt-3 text-[11px] text-tf-secondary">
          {t('dashboard.confirm.undo_hint')}
        </p>
        <div className="mt-5 flex justify-end gap-2 border-t border-tf-border pt-4">
          <button
            type="button"
            onClick={onCancel}
            className="tf-surface-alt px-4 py-2 text-xs font-semibold text-tf-secondary hover:text-tf-primary"
          >
            {t('dashboard.confirm.cancel')}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="tf-btn-accent px-5 py-2 text-xs font-bold"
          >
            {t('dashboard.confirm.apply')}
          </button>
        </div>
      </div>
    </ModalContainer>
  );
};
