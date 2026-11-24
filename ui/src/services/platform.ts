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

/** Operating systems for which the desktop UI can start or verify the background daemon. */
export const DAEMON_START_OS_NAMES: readonly string[] = ['WINDOWS', 'LINUX'];

export function canStartDaemonFromUi(osName: string): boolean {
  return DAEMON_START_OS_NAMES.includes(osName);
}
