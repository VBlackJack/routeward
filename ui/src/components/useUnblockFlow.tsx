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

import React, { useCallback, useState } from 'react';
import { getFriendlyAppName, Translate } from '../services/friendly';
import {
  buildPreviewRequest,
  buildUnblockPlan,
  describePlanChanges,
  UnblockCommand,
  UnblockDuration,
  UnblockOption,
  UnblockPlan,
  UnblockTarget
} from '../services/unblockPlan';
import {
  PreviewRuleChangeRequest,
  PreviewRuleChangeResponse,
  ProxyChain,
  ProxyNode,
  RoutingRule,
  ToastNotification
} from '../types/routeward';
import { UnblockConfirm } from './UnblockConfirm';

export interface UnblockFlowDeps {
  rules: RoutingRule[];
  proxies: ProxyNode[];
  chains: ProxyChain[];
  t: Translate;
  previewRuleChange: (
    req: PreviewRuleChangeRequest
  ) => Promise<PreviewRuleChangeResponse | null>;
  upsertRule: (rule: RoutingRule) => Promise<unknown>;
  removeRule: (ruleId: string) => Promise<unknown>;
  /** Runs an option that is not a rule change (test the proxy, open it, pause, flush DNS). */
  onCommand: (command: UnblockCommand, target: UnblockTarget) => void;
  notify: (
    message: string,
    severity: ToastNotification['severity'],
    action?: { label: string; onAction: () => void }
  ) => void;
  onError: (err: unknown) => void;
}

interface PendingUnblock {
  subject: string;
  plan: UnblockPlan;
  changes: string[];
  preview: PreviewRuleChangeResponse | null;
}

/** Applies a set of rule changes one call at a time with the existing upsert and remove calls. */
async function applyChanges(
  deps: Pick<UnblockFlowDeps, 'upsertRule' | 'removeRule'>,
  upserts: RoutingRule[],
  removeIds: string[]
): Promise<void> {
  for (const rule of upserts) {
    await deps.upsertRule(rule);
  }
  for (const id of removeIds) {
    await deps.removeRule(id);
  }
}

/**
 * The Unblock flow: pick an option, preview the change with the daemon, confirm, apply, and
 * offer an undo. `element` is the confirmation dialog to render, or null.
 */
export function useUnblockFlow(deps: UnblockFlowDeps): {
  choose: (target: UnblockTarget, option: UnblockOption, duration: UnblockDuration) => Promise<void>;
  element: React.ReactElement | null;
} {
  const [pending, setPending] = useState<PendingUnblock | null>(null);
  const { t } = deps;

  const choose = useCallback(
    async (
      target: UnblockTarget,
      option: UnblockOption,
      duration: UnblockDuration
    ): Promise<void> => {
      if (option.command) {
        deps.onCommand(option.command, target);
        return;
      }
      const plan = buildUnblockPlan(target, option, duration, {
        rules: deps.rules,
        proxies: deps.proxies,
        chains: deps.chains,
        t: deps.t
      });
      if (!plan) {
        return;
      }
      const preview = await deps
        .previewRuleChange({
          upserts: plan.upserts,
          removeIds: plan.removeIds,
          request: buildPreviewRequest(target)
        })
        .catch(() => null);
      const siteOnly = option.kind === 'exceptionSite';
      setPending({
        subject: siteOnly
          ? target.destination
          : getFriendlyAppName(target.processName).displayName,
        plan,
        changes: describePlanChanges(plan, deps.rules, deps.t),
        preview
      });
    },
    [deps]
  );

  const confirm = (current: PendingUnblock) => {
    setPending(null);
    applyChanges(deps, current.plan.upserts, current.plan.removeIds)
      .then(() => {
        deps.notify(t('unblock.toast.done', { name: current.subject }), 'success', {
          label: t('app.toast.undo'),
          onAction: () => {
            applyChanges(deps, current.plan.undoUpserts, current.plan.undoRemoveIds)
              .then(() => deps.notify(t('app.toast.undo_applied'), 'info'))
              .catch(deps.onError);
          }
        });
      })
      .catch(deps.onError);
  };

  const element = pending ? (
    <UnblockConfirm
      subject={pending.subject}
      changes={pending.changes}
      preview={pending.preview}
      onConfirm={() => confirm(pending)}
      onCancel={() => setPending(null)}
    />
  ) : null;

  return { choose, element };
}
