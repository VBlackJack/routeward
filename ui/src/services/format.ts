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

import i18n from '../i18n';
import { UI_CONFIG } from '../config/constants';

/** Matches the `HH:MM:SS` UTC time-of-day strings produced by the telemetry sampler. */
const UTC_TIME_OF_DAY_PATTERN = /^(\d{2}):(\d{2}):(\d{2})$/;

function currentLocale(): string {
  return i18n.language || UI_CONFIG.DEFAULT_LOCALE;
}

/** Formats a byte count with the locale decimal separator and the localized unit label. */
export function formatBytes(bytes: number): string {
  const unitKeys = UI_CONFIG.BYTE_UNIT_KEYS;
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return `0 ${i18n.t(unitKeys[0])}`;
  }
  const unitIndex = Math.min(
    unitKeys.length - 1,
    Math.floor(Math.log(bytes) / Math.log(UI_CONFIG.BYTE_STEP))
  );
  const value = bytes / Math.pow(UI_CONFIG.BYTE_STEP, unitIndex);
  const fractionDigits = unitIndex === 0 ? 0 : 1;
  const number = new Intl.NumberFormat(currentLocale(), {
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
    useGrouping: false
  }).format(value);
  return `${number} ${i18n.t(unitKeys[unitIndex])}`;
}

/** Formats an ISO timestamp as a localized wall-clock time; returns the input when unparsable. */
export function formatLogTime(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }
  return new Intl.DateTimeFormat(currentLocale(), { timeStyle: 'medium' }).format(date);
}

/**
 * Formats a bandwidth sample timestamp. The sampler emits `HH:MM:SS` in UTC, which is
 * converted to the local wall-clock time; any other shape is returned unchanged.
 */
export function formatSampleTime(timestamp: string, now: Date = new Date()): string {
  const match = UTC_TIME_OF_DAY_PATTERN.exec(timestamp);
  if (!match) {
    return timestamp;
  }
  const date = new Date(
    Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
      Number(match[1]),
      Number(match[2]),
      Number(match[3])
    )
  );
  if (Number.isNaN(date.getTime())) {
    return timestamp;
  }
  return new Intl.DateTimeFormat(currentLocale(), { timeStyle: 'medium' }).format(date);
}
