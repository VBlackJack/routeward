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

import { TrackedConnection } from '../types/routeward';
import { describeBlockReason } from './blockReason';
import { localizeEngineRuleName, Translate } from './friendly';

export interface ConnectionExplanation {
  /** Name of the rule that decided, in plain words; null when the engine did not report one. */
  ruleName: string | null;
  /** Locale key of the translated reason. */
  reasonKey: string;
}

/** True when the connection did not work, so a beginner may ask why. */
export function connectionNeedsExplanation(conn: TrackedConnection): boolean {
  return conn.status === 'blocked' || Boolean(conn.errorDetail);
}

/** Explains a blocked or failed connection: which rule applied and why it ended that way. */
export function explainConnection(
  conn: TrackedConnection,
  t: Translate
): ConnectionExplanation {
  const rawRule = conn.matchedRule?.trim() ?? '';
  return {
    ruleName: rawRule ? localizeEngineRuleName(rawRule, t) : null,
    reasonKey: describeBlockReason(conn.blockReason, conn.errorDetail).bodyKey
  };
}

/** The most recent failed or blocked connection of an application, if it has one. */
export function findConnectionToExplain(
  connections: TrackedConnection[],
  processName: string
): TrackedConnection | null {
  const wanted = processName.toLowerCase();
  return (
    connections.find(
      (c) =>
        c.processName.toLowerCase() === wanted && connectionNeedsExplanation(c)
    ) ?? null
  );
}
