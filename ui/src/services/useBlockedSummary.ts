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

import { useCallback, useEffect, useRef, useState } from 'react';
import { UI_CONFIG } from '../config/constants';
import { BlockedCounters, BlockedResponse, BlockedSummaryEntry } from '../types/routeward';

export interface BlockedSummaryState {
  entries: BlockedSummaryEntry[];
  counters: BlockedCounters | null;
  loading: boolean;
  error: boolean;
  refresh: () => void;
}

/**
 * Loads the blocked summary while `active` is true and refreshes it on a timer.
 * `load` must keep the same identity between renders (it restarts the timer otherwise).
 */
export function useBlockedSummary(
  active: boolean,
  load: () => Promise<BlockedResponse | null>
): BlockedSummaryState {
  const [entries, setEntries] = useState<BlockedSummaryEntry[]>([]);
  const [counters, setCounters] = useState<BlockedCounters | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(() => {
    setLoading(true);
    load()
      .then((res) => {
        if (!mounted.current) return;
        if (res) {
          setEntries(res.entries ?? []);
          setCounters(res.counters ?? null);
          setError(false);
        } else {
          setError(true);
        }
      })
      .catch(() => {
        if (mounted.current) setError(true);
      })
      .finally(() => {
        if (mounted.current) setLoading(false);
      });
  }, [load]);

  useEffect(() => {
    if (!active) {
      return;
    }
    refresh();
    const timer = window.setInterval(refresh, UI_CONFIG.BLOCKED_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [active, refresh]);

  return { entries, counters, loading, error, refresh };
}
