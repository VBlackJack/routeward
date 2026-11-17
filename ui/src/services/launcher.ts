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

const LINE_BREAK_PATTERN = /\r\n|\r|\n/;

/**
 * Turns the launcher textarea content into an argument list: one argument per line,
 * no shell-style parsing. Only empty lines are dropped; spaces inside a line are kept.
 */
export function parseLauncherArgs(raw: string): string[] {
  return raw.split(LINE_BREAK_PATTERN).filter((line) => line.length > 0);
}

/** Inverse of {@link parseLauncherArgs}, used to fill the textarea from a preset. */
export function formatLauncherArgs(args: readonly string[]): string {
  return args.join('\n');
}
