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

export type ActivitySubtab = 'connections' | 'blocked';

interface ActivitySubtabsProps {
  value: ActivitySubtab;
  onChange: (value: ActivitySubtab) => void;
  /** Number of connections blocked so far, shown as a badge on the Blocked tab. */
  blockedCount?: number;
}

/** Switches the Activity page between the connection list and the Blocked tab. */
export const ActivitySubtabs: React.FC<ActivitySubtabsProps> = ({
  value,
  onChange,
  blockedCount = 0
}) => {
  const { t } = useTranslation();
  const tabs: Array<{ id: ActivitySubtab; label: string }> = [
    { id: 'connections', label: t('activity.subtabs.connections') },
    { id: 'blocked', label: t('activity.subtabs.blocked') }
  ];
  return (
    <div
      role="group"
      aria-label={t('activity.subtabs.label')}
      className="mb-4 flex flex-wrap gap-2"
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          aria-pressed={value === tab.id}
          onClick={() => onChange(tab.id)}
          className={`rounded-tf-md px-3 py-1.5 text-xs font-semibold transition ${
            value === tab.id
              ? 'bg-tf-accent text-tf-bg'
              : 'tf-surface-alt text-tf-secondary hover:text-tf-primary'
          }`}
        >
          {tab.label}
          {tab.id === 'blocked' && blockedCount > 0 ? ` (${blockedCount})` : ''}
        </button>
      ))}
    </div>
  );
};
