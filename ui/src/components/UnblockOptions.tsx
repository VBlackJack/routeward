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

import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UnblockDuration, UnblockOption, UNBLOCK_DURATIONS } from '../services/unblockPlan';

interface UnblockOptionsProps {
  options: UnblockOption[];
  /** Plain-language explanation shown when nothing can be changed (explanation-only reasons). */
  explanation: string;
  onChoose: (option: UnblockOption, duration: UnblockDuration) => void;
}

const DURATION_LABEL_KEYS: Record<UnblockDuration, string> = {
  minutes15: 'unblock.duration.minutes15',
  hour1: 'unblock.duration.hour1',
  always: 'unblock.duration.always'
};

const RISK_CLASSES: Record<UnblockOption['risk'], string> = {
  normal: 'border-tf-border hover:border-tf-accent',
  impact: 'border-tf-orange/50 hover:border-tf-orange',
  unprotected: 'border-tf-red/60 hover:border-tf-red'
};

/** The choices offered for one blocked item, with the "for how long" selector. */
export const UnblockOptions: React.FC<UnblockOptionsProps> = ({
  options,
  explanation,
  onChoose
}) => {
  const { t } = useTranslation();
  const [duration, setDuration] = useState<UnblockDuration>('hour1');
  const canLimit = options.some((o) => o.supportsDuration);

  if (options.length === 0) {
    return (
      <p className="rounded-tf-md border border-tf-border bg-tf-surface-alt p-3 text-xs text-tf-primary">
        {explanation}
      </p>
    );
  }

  return (
    <div className="space-y-3 rounded-tf-md border border-tf-border bg-tf-surface-alt p-3">
      {canLimit && (
        <fieldset className="flex flex-wrap items-center gap-3 text-xs text-tf-primary">
          <legend className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-tf-secondary">
            {t('unblock.duration.legend')}
          </legend>
          {UNBLOCK_DURATIONS.map((value) => (
            <label key={value} className="flex items-center gap-1.5">
              <input
                type="radio"
                name="unblock-duration"
                value={value}
                checked={duration === value}
                onChange={() => setDuration(value)}
              />
              {t(DURATION_LABEL_KEYS[value])}
            </label>
          ))}
        </fieldset>
      )}
      <ul className="space-y-2">
        {options.map((option) => (
          <li key={option.id}>
            <button
              type="button"
              onClick={() => onChoose(option, duration)}
              disabled={option.command === 'none'}
              className={`w-full rounded-tf-md border bg-tf-surface p-2.5 text-left text-xs transition disabled:cursor-default disabled:opacity-90 ${RISK_CLASSES[option.risk]}`}
            >
              <span className="block font-semibold text-tf-primary">
                {t(option.titleKey, option.params)}
              </span>
              <span
                className={`mt-0.5 block ${
                  option.risk === 'unprotected' ? 'text-tf-red' : 'text-tf-secondary'
                }`}
              >
                {t(option.descKey, option.params)}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
};
