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
import { ShieldAlert } from 'lucide-react';

interface BlockedShortcutProps {
  /** Number of connections blocked so far; the shortcut is hidden at zero. */
  blockedCount: number;
  onOpen?: () => void;
}

/** Home shortcut to the Blocked tab, shown only when something was blocked. */
export const BlockedShortcut: React.FC<BlockedShortcutProps> = ({
  blockedCount,
  onOpen
}) => {
  const { t } = useTranslation();
  if (!onOpen || blockedCount <= 0) {
    return null;
  }
  return (
    <div className="tf-card flex flex-wrap items-center justify-between gap-3 border-l-4 border-l-tf-orange p-4">
      <div className="flex items-center gap-2 text-xs text-tf-primary">
        <ShieldAlert className="h-4 w-4 text-tf-orange" />
        <span>{t('blocked.home.text', { count: blockedCount })}</span>
      </div>
      <button
        type="button"
        onClick={onOpen}
        className="tf-surface-alt px-3 py-1.5 text-xs font-semibold text-tf-orange hover:border-tf-orange"
      >
        {t('blocked.home.cta')}
      </button>
    </div>
  );
};
