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

const MS_PER_MINUTE = 60_000;
const MINUTES_PER_HOUR = 60;

export interface RemainingTime {
  hours: number;
  minutes: number;
}

/** Time left before a temporary rule stops, or null when it has no expiry, a bad one, or is over. */
export function remainingTime(
  expiresAt: string | null | undefined,
  now: number
): RemainingTime | null {
  if (!expiresAt) {
    return null;
  }
  const end = Date.parse(expiresAt);
  if (Number.isNaN(end) || end <= now) {
    return null;
  }
  const totalMinutes = Math.ceil((end - now) / MS_PER_MINUTE);
  return {
    hours: Math.floor(totalMinutes / MINUTES_PER_HOUR),
    minutes: totalMinutes % MINUTES_PER_HOUR
  };
}

/** Locale key and parameters that say how long is left, in plain words. */
export function remainingTimeText(left: RemainingTime): {
  key: string;
  params: Record<string, number>;
} {
  if (left.hours > 0) {
    return {
      key: 'rules.temporary.hours_minutes',
      params: { hours: left.hours, minutes: left.minutes }
    };
  }
  return { key: 'rules.temporary.minutes', params: { count: left.minutes } };
}
