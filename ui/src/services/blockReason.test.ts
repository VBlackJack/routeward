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

import { describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { TrackedConnection } from '../types/routeward';
import { explainConnection } from './activityWhy';
import {
  connectionBlockInfo,
  describeBlockReason,
  isKnownBlockReason,
  isProxyOutageReason,
  KNOWN_BLOCK_REASONS
} from './blockReason';

function conn(partial: Partial<TrackedConnection>): TrackedConnection {
  return {
    id: 'c1',
    pid: 10,
    processName: 'chrome.exe',
    processPath: 'C:/chrome.exe',
    targetHost: 'example.com',
    resolvedDomain: null,
    targetPort: 443,
    protocol: 'tcp',
    matchedRule: 'Block ads',
    routeLabel: 'BLOCKED',
    latencyMs: 0,
    rxBytes: 0,
    txBytes: 0,
    status: 'blocked',
    startedAt: '2026-11-22T10:00:00Z',
    ...partial
  };
}

describe('blockReason mapping', () => {
  it('maps every reason to existing English and French texts', () => {
    expect(KNOWN_BLOCK_REASONS).toHaveLength(18);
    for (const lng of ['en', 'fr']) {
      for (const reason of KNOWN_BLOCK_REASONS) {
        const info = describeBlockReason(reason);
        expect(info.reason).toBe(reason);
        expect(info.titleKey).toBe(`blocked.reasons.${reason}.title`);
        expect(info.bodyKey).toBe(`blocked.reasons.${reason}.body`);
        expect(i18n.exists(info.titleKey, { lng })).toBe(true);
        expect(i18n.exists(info.bodyKey, { lng })).toBe(true);
        expect(info.fixes.length).toBeGreaterThan(0);
      }
    }
  });

  it('marks proxy outage reasons as critical and explanation-only reasons as info', () => {
    expect(describeBlockReason('killSwitchProxyTimeout').severity).toBe('critical');
    expect(describeBlockReason('quicBlocked').severity).toBe('info');
    expect(describeBlockReason('quicBlocked').fixes).toEqual(['explainOnly']);
  });

  it('falls back to the error-based text for a missing or unknown reason', () => {
    expect(describeBlockReason(undefined, 'proxy timed out').bodyKey).toBe(
      'troubleshoot.reasons.timeout'
    );
    expect(describeBlockReason(undefined).bodyKey).toBe('troubleshoot.reasons.blocked_by_rule');
    expect(describeBlockReason('unknown').titleKey).toBe('blocked.reasons.unknown.title');
    expect(describeBlockReason('somethingNew' as never).reason).toBe('unknown');
    expect(isKnownBlockReason('somethingNew')).toBe(false);
    expect(isKnownBlockReason('ruleBlock')).toBe(true);
  });

  it('recognizes proxy outage reasons only', () => {
    expect(isProxyOutageReason('killSwitchProxyRefused')).toBe(true);
    expect(isProxyOutageReason('udpProxyUnsupported')).toBe(false);
    expect(isProxyOutageReason('killSwitchDirectUdpFailed')).toBe(false);
    expect(isProxyOutageReason('killSwitchProxyAuthRejected')).toBe(true);
    expect(isProxyOutageReason('killSwitchProxyMisconfigured')).toBe(true);
    expect(isProxyOutageReason(undefined)).toBe(false);
  });

  it('describes a connection only when it failed or was blocked', () => {
    expect(connectionBlockInfo(conn({ status: 'active' }))).toBeNull();
    expect(connectionBlockInfo(conn({ blockReason: 'ruleBlock' }))?.reason).toBe('ruleBlock');
  });

  it('uses the reason, not the error text, in the activity explanation', () => {
    const explained = explainConnection(
      conn({ blockReason: 'quicBlocked', errorDetail: 'proxy timed out' }),
      (key) => key
    );
    expect(explained.reasonKey).toBe('blocked.reasons.quicBlocked.body');
  });

  it('keeps the old guess for a record without a reason', () => {
    const explained = explainConnection(
      conn({ errorDetail: 'proxy timed out' }),
      (key) => key
    );
    expect(explained.reasonKey).toBe('troubleshoot.reasons.timeout');
  });
});
