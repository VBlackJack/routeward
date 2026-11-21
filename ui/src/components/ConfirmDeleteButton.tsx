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

import React, { useEffect, useRef } from 'react';
import { Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface ConfirmDeleteButtonProps {
  /** Whether this item is currently armed for confirmation. */
  armed: boolean;
  /** Accessible label for the initial delete icon button. */
  ariaLabel: string;
  /** Tooltip title for the initial delete icon button. */
  title: string;
  /** Optional short warning shown next to the confirm button when armed. */
  warningText?: string;
  /** Called when the user clicks the delete icon to arm confirmation. */
  onArm: () => void;
  /** Called when the user confirms deletion. */
  onConfirm: () => void;
  /** Called when the user cancels confirmation (button or Escape). */
  onCancel: () => void;
}

/**
 * Keyboard-accessible 2-step inline delete control: first click arms a
 * Confirm / Cancel pair; Escape or Cancel disarms without deleting.
 */
export const ConfirmDeleteButton: React.FC<ConfirmDeleteButtonProps> = ({
  armed,
  ariaLabel,
  title,
  warningText,
  onArm,
  onConfirm,
  onCancel
}) => {
  const { t } = useTranslation();
  const armButtonRef = useRef<HTMLButtonElement | null>(null);
  const cancelButtonRef = useRef<HTMLButtonElement | null>(null);
  const wasArmedRef = useRef(false);
  const restoreOnDisarmRef = useRef(false);

  useEffect(() => {
    if (armed && !wasArmedRef.current) {
      cancelButtonRef.current?.focus();
    } else if (!armed && wasArmedRef.current && restoreOnDisarmRef.current) {
      restoreOnDisarmRef.current = false;
      armButtonRef.current?.focus();
    }
    wasArmedRef.current = armed;
  }, [armed]);

  const handleCancel = () => {
    restoreOnDisarmRef.current = true;
    onCancel();
  };

  if (!armed) {
    return (
      <button
        ref={armButtonRef}
        type="button"
        onClick={onArm}
        title={title}
        aria-label={ariaLabel}
        className="rounded p-1.5 text-tf-secondary transition hover:bg-tf-surface-alt hover:text-tf-red"
      >
        <Trash2 className="h-4 w-4" />
      </button>
    );
  }

  return (
    <span
      className="inline-flex flex-wrap items-center gap-1.5"
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation();
          handleCancel();
        }
      }}
    >
      {warningText && (
        <span className="rounded bg-tf-orange/15 px-1.5 py-0.5 text-[10px] font-semibold text-tf-orange">
          {warningText}
        </span>
      )}
      <button
        type="button"
        onClick={onConfirm}
        aria-label={`${t('app.confirm_delete.confirm')}: ${ariaLabel}`}
        className="rounded-tf-sm bg-tf-red px-2 py-1 text-[11px] font-bold text-tf-bg transition hover:opacity-90"
      >
        {t('app.confirm_delete.confirm')}
      </button>
      <button
        ref={cancelButtonRef}
        type="button"
        onClick={handleCancel}
        aria-label={`${t('app.confirm_delete.cancel')}: ${ariaLabel}`}
        className="rounded-tf-sm border border-tf-border bg-tf-surface-alt px-2 py-1 text-[11px] font-semibold text-tf-secondary hover:text-tf-primary"
      >
        {t('app.confirm_delete.cancel')}
      </button>
    </span>
  );
};
