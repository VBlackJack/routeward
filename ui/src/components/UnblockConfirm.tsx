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
import { describeBlockReason } from '../services/blockReason';
import {
  BlockReason,
  PreviewRuleChangeResponse
} from '../types/routeward';
import { ConfirmApplyModal } from './ConfirmApplyModal';

interface UnblockConfirmProps {
  /** Plain name of the app or site being unblocked. */
  subject: string;
  /** One line per rule change (the rule diff). */
  changes: string[];
  /** The daemon's prediction; null when the preview was not available. */
  preview: PreviewRuleChangeResponse | null;
  onConfirm: () => void;
  onCancel: () => void;
}

type PredictedOutcome = 'direct' | 'proxy' | 'block' | 'unknown';

function predictOutcome(preview: PreviewRuleChangeResponse | null): PredictedOutcome {
  if (!preview) {
    return 'unknown';
  }
  const type = preview.evaluation.action.type;
  if (type === 'direct') return 'direct';
  if (type === 'block') return 'block';
  return 'proxy';
}

/** Shows the rule diff and the predicted outcome before an unblock is applied. */
export const UnblockConfirm: React.FC<UnblockConfirmProps> = ({
  subject,
  changes,
  preview,
  onConfirm,
  onCancel
}) => {
  const { t } = useTranslation();
  const outcome = predictOutcome(preview);
  const outcomeLine =
    outcome === 'direct'
      ? t('unblock.confirm.outcome_direct')
      : outcome === 'proxy'
        ? t('unblock.confirm.outcome_proxy')
        : outcome === 'block'
          ? t('unblock.confirm.outcome_block')
          : t('unblock.confirm.outcome_unknown');
  const override: BlockReason | undefined = preview?.policyOverride;
  const warning = override
    ? t('unblock.confirm.override_warning', {
        reason: t(describeBlockReason(override).titleKey)
      })
    : outcome === 'block'
      ? t('unblock.confirm.still_blocked_warning')
      : undefined;

  return (
    <ConfirmApplyModal
      title={t('unblock.confirm.title', { name: subject })}
      intro={t('unblock.confirm.intro')}
      changes={[...changes, outcomeLine]}
      warning={warning}
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
  );
};
