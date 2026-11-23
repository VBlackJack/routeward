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

import { IpcStreamEvent } from '../types/routeward';

export interface ParsedSseFrame {
  event: string;
  data: string;
}

export function parseSseChunk(buffer: string): {
  events: ParsedSseFrame[];
  remainder: string;
} {
  const normalized = buffer.replace(/\r\n/g, '\n');
  const frames = normalized.split('\n\n');
  const remainder = frames.pop() ?? '';
  const events: ParsedSseFrame[] = [];

  for (const rawFrame of frames) {
    const lines = rawFrame.split('\n');
    let eventName = 'message';
    const dataLines: string[] = [];

    for (const line of lines) {
      if (!line || line.startsWith(':')) {
        continue;
      }
      if (line.startsWith('event:')) {
        eventName = line.slice('event:'.length).trim();
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trim());
      }
    }

    if (dataLines.length > 0) {
      events.push({
        event: eventName,
        data: dataLines.join('\n')
      });
    }
  }

  return { events, remainder };
}

export interface RealtimeSseLoopOptions {
  endpoint: string;
  headers: () => Record<string, string>;
  reconnectDelayMs: number;
  fetchState: () => Promise<void>;
  onDisconnected: () => void;
  onStreamEvent: (streamEvent: IpcStreamEvent) => boolean;
}

export async function runRealtimeSseLoop(
  options: RealtimeSseLoopOptions,
  abortSignal?: AbortSignal
): Promise<void> {
  while (!abortSignal?.aborted) {
    await options.fetchState();
    if (abortSignal?.aborted) {
      break;
    }

    try {
      const response = await fetch(options.endpoint, {
        method: 'GET',
        headers: options.headers(),
        cache: 'no-store',
        signal: abortSignal
      });

      if (!response.ok || !response.body) {
        options.onDisconnected();
      } else {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (!abortSignal?.aborted) {
          const { value, done } = await reader.read();
          if (done) {
            break;
          }
          buffer += decoder.decode(value, { stream: true });
          const parsed = parseSseChunk(buffer);
          buffer = parsed.remainder;

          for (const frame of parsed.events) {
            if (frame.event === 'resync') {
              await options.fetchState();
              continue;
            }
            try {
              const streamEv = JSON.parse(frame.data) as IpcStreamEvent;
              if (options.onStreamEvent(streamEv)) {
                await options.fetchState();
              }
            } catch {
              // Ignore malformed frame
            }
          }
        }
      }
    } catch {
      if (!abortSignal?.aborted) {
        options.onDisconnected();
      }
    }

    if (abortSignal?.aborted) {
      break;
    }
    await new Promise<void>((resolve) => {
      const timer = window.setTimeout(() => {
        abortSignal?.removeEventListener('abort', onAbort);
        resolve();
      }, options.reconnectDelayMs);
      const onAbort = () => {
        window.clearTimeout(timer);
        resolve();
      };
      abortSignal?.addEventListener('abort', onAbort, { once: true });
    });
  }
}
