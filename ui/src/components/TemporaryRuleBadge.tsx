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

import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Timer } from 'lucide-react';
import { UI_CONFIG } from '../config/constants';
import { remainingTime, remainingTimeText } from '../services/ruleExpiry';

interface TemporaryRuleBadgeProps {
  expiresAt?: string | null;
}

/** Marks a rule that stops by itself, with the time left. Renders nothing for a permanent rule. */
export const TemporaryRuleBadge: React.FC<TemporaryRuleBadgeProps> = ({ expiresAt }) => {
  const { t } = useTranslation();
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!expiresAt) {
      return undefined;
    }
    const timer = window.setInterval(() => setNow(Date.now()), UI_CONFIG.TEMPORARY_RULE_TICK_MS);
    return () => window.clearInterval(timer);
  }, [expiresAt]);

  const left = remainingTime(expiresAt, now);
  if (!left) {
    return null;
  }
  const text = remainingTimeText(left);
  return (
    <span
      data-testid="temporary-rule-badge"
      className="ml-2 inline-flex items-center gap-1 rounded bg-tf-orange/15 px-1.5 py-0.5 text-[10px] font-semibold text-tf-orange"
    >
      <Timer className="h-3 w-3" />
      {t('rules.temporary.badge', { time: t(text.key, text.params) })}
    </span>
  );
};
