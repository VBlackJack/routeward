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

import { BlockReason, TrackedConnection } from '../types/routeward';
import { getHumanErrorKey } from './friendly';

export type BlockSeverity = 'info' | 'warning' | 'critical';

/** What a person can do about a block; the unblock plan decides which ones apply to a given record. */
export type BlockFix =
  | 'changeRule'
  | 'exception'
  | 'disableRule'
  | 'testProxy'
  | 'openProxy'
  | 'appDirect'
  | 'pause'
  | 'flushDns'
  | 'restartApp'
  | 'explainOnly';

export interface BlockReasonInfo {
  reason: BlockReason;
  titleKey: string;
  bodyKey: string;
  severity: BlockSeverity;
  fixes: BlockFix[];
}

/** Every reason the engine can report, in the order they are documented. */
export const KNOWN_BLOCK_REASONS: readonly BlockReason[] = [
  'ruleBlock',
  'defaultPolicyBlock',
  'killSwitchProxyUnreachable',
  'killSwitchProxyRefused',
  'killSwitchProxyTimeout',
  'killSwitchProxyAuthRejected',
  'killSwitchProxyHandshake',
  'killSwitchProxyMisconfigured',
  'killSwitchUdpUnsupported',
  'killSwitchDirectUdpFailed',
  'fragmentedUdpBlocked',
  'unknownProcessPolicy',
  'unknownProcessKillSwitch',
  'fakeIpEgressGuard',
  'quicBlocked',
  'encryptedDnsBlocked',
  'localNameGuard',
  'dnsServerBlockedByRule'
];

const PROXY_OUTAGE_FIXES: BlockFix[] = ['testProxy', 'openProxy', 'appDirect', 'pause'];

const REASON_TABLE: Record<
  Exclude<BlockReason, 'unknown'>,
  { severity: BlockSeverity; fixes: BlockFix[] }
> = {
  ruleBlock: { severity: 'warning', fixes: ['changeRule', 'exception', 'disableRule'] },
  defaultPolicyBlock: { severity: 'warning', fixes: ['exception'] },
  killSwitchProxyUnreachable: { severity: 'critical', fixes: PROXY_OUTAGE_FIXES },
  killSwitchProxyRefused: { severity: 'critical', fixes: PROXY_OUTAGE_FIXES },
  killSwitchProxyTimeout: { severity: 'critical', fixes: PROXY_OUTAGE_FIXES },
  killSwitchProxyAuthRejected: { severity: 'critical', fixes: ['openProxy', 'testProxy'] },
  killSwitchProxyHandshake: { severity: 'critical', fixes: PROXY_OUTAGE_FIXES },
  killSwitchProxyMisconfigured: { severity: 'critical', fixes: ['openProxy'] },
  killSwitchUdpUnsupported: { severity: 'warning', fixes: ['appDirect', 'openProxy'] },
  killSwitchDirectUdpFailed: { severity: 'warning', fixes: ['testProxy', 'openProxy'] },
  fragmentedUdpBlocked: { severity: 'warning', fixes: ['appDirect', 'openProxy'] },
  unknownProcessPolicy: { severity: 'info', fixes: ['explainOnly'] },
  unknownProcessKillSwitch: { severity: 'info', fixes: ['explainOnly'] },
  fakeIpEgressGuard: { severity: 'warning', fixes: ['flushDns', 'restartApp'] },
  quicBlocked: { severity: 'info', fixes: ['explainOnly'] },
  encryptedDnsBlocked: { severity: 'info', fixes: ['explainOnly'] },
  localNameGuard: { severity: 'info', fixes: ['explainOnly'] },
  dnsServerBlockedByRule: {
    severity: 'warning',
    fixes: ['changeRule', 'exception', 'disableRule']
  }
};

const REASON_KEY_PREFIX = 'blocked.reasons.';

/** True when the daemon sent a reason this UI knows how to explain. */
export function isKnownBlockReason(
  reason: unknown
): reason is Exclude<BlockReason, 'unknown'> {
  return (
    typeof reason === 'string' &&
    Object.prototype.hasOwnProperty.call(REASON_TABLE, reason)
  );
}

/** True for the kill switch reasons caused by an unhealthy upstream proxy. */
export function isProxyOutageReason(reason: BlockReason | undefined): boolean {
  return Boolean(reason && reason.startsWith('killSwitchProxy'));
}

/**
 * Maps a reason to its locale keys, severity and fixes. A missing or unknown reason (an older
 * daemon) falls back to the generic text, with the body guessed from the raw error as before.
 */
export function describeBlockReason(
  reason: BlockReason | undefined,
  errorDetail?: string | null
): BlockReasonInfo {
  if (isKnownBlockReason(reason)) {
    const row = REASON_TABLE[reason];
    return {
      reason,
      titleKey: `${REASON_KEY_PREFIX}${reason}.title`,
      bodyKey: `${REASON_KEY_PREFIX}${reason}.body`,
      severity: row.severity,
      fixes: row.fixes
    };
  }
  return {
    reason: 'unknown',
    titleKey: `${REASON_KEY_PREFIX}unknown.title`,
    bodyKey: getHumanErrorKey(errorDetail),
    severity: 'warning',
    fixes: ['explainOnly']
  };
}

/** Reason description of a failed or blocked connection, or null for a connection that worked. */
export function connectionBlockInfo(conn: TrackedConnection): BlockReasonInfo | null {
  if (conn.status !== 'blocked' && !conn.errorDetail) {
    return null;
  }
  return describeBlockReason(conn.blockReason, conn.errorDetail);
}
