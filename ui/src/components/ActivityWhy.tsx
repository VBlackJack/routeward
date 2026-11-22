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
import { HelpCircle } from 'lucide-react';
import {
  connectionNeedsExplanation,
  explainConnection
} from '../services/activityWhy';
import { TrackedConnection } from '../types/routeward';

interface ActivityWhyProps {
  connection: TrackedConnection;
}

/** "Why?" answer for an app whose connection failed or was blocked (nothing for working apps). */
export const ActivityWhy: React.FC<ActivityWhyProps> = ({ connection }) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const panelId = useId();

  if (!connectionNeedsExplanation(connection)) {
    return null;
  }
  const explanation = explainConnection(connection, t);

  return (
    <div className="w-full">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((prev) => !prev)}
        className="flex items-center gap-1.5 text-[11px] font-semibold text-tf-orange hover:underline"
      >
        <HelpCircle className="h-3.5 w-3.5" />
        {t('troubleshoot.why.button')}
      </button>
      {open && (
        <div
          id={panelId}
          className="mt-1.5 space-y-1 rounded-tf-md border border-tf-orange/30 bg-tf-orange/10 p-2.5 text-[11px] text-tf-primary"
        >
          <p>{t(explanation.reasonKey)}</p>
          <p className="text-tf-secondary">
            {explanation.ruleName
              ? t('troubleshoot.why.rule', { name: explanation.ruleName })
              : t('troubleshoot.why.no_rule')}
          </p>
        </div>
      )}
    </div>
  );
};
