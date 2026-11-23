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
import { remainingTime, remainingTimeText } from './ruleExpiry';

const NOW = Date.UTC(2026, 10, 22, 10, 0, 0);

describe('remainingTime', () => {
  it('is null without an expiry, with a bad one, or once it has passed', () => {
    expect(remainingTime(undefined, NOW)).toBeNull();
    expect(remainingTime(null, NOW)).toBeNull();
    expect(remainingTime('not a date', NOW)).toBeNull();
    expect(remainingTime(new Date(NOW).toISOString(), NOW)).toBeNull();
    expect(remainingTime(new Date(NOW - 1000).toISOString(), NOW)).toBeNull();
  });

  it('rounds up to whole minutes and splits hours', () => {
    expect(remainingTime(new Date(NOW + 15 * 60_000).toISOString(), NOW)).toEqual({
      hours: 0,
      minutes: 15
    });
    expect(remainingTime(new Date(NOW + 30_000).toISOString(), NOW)).toEqual({
      hours: 0,
      minutes: 1
    });
    expect(remainingTime(new Date(NOW + 75 * 60_000).toISOString(), NOW)).toEqual({
      hours: 1,
      minutes: 15
    });
  });

  it('picks the locale key by size', () => {
    expect(remainingTimeText({ hours: 0, minutes: 5 }).key).toBe('rules.temporary.minutes');
    expect(remainingTimeText({ hours: 1, minutes: 0 }).key).toBe('rules.temporary.hours_minutes');
  });
});
