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

import { useEffect, useState } from 'react';
import { UI_CONFIG } from '../config/constants';
import { secondsUntil } from './protectionHealth';

/**
 * Seconds left until `deadlineEpochMs`, refreshed every second while a deadline exists.
 * Display only: the daemon owns the deadline and resumes protection by itself.
 */
export function usePauseCountdown(deadlineEpochMs: number | null): number | null {
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    if (deadlineEpochMs === null) {
      return;
    }
    setNowMs(Date.now());
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, UI_CONFIG.PAUSE_COUNTDOWN_TICK_MS);
    return () => window.clearInterval(timer);
  }, [deadlineEpochMs]);

  return deadlineEpochMs === null ? null : secondsUntil(deadlineEpochMs, nowMs);
}
