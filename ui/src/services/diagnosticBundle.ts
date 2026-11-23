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

import { UI_CONFIG } from '../config/constants';
import { DiagnosticBundle, DiagnosticSectionInfo } from '../types/routeward';

const DATE_PAD = 2;

/**
 * Reads the sections (name and size in bytes) from the manifest. The manifest may list them as
 * an array of { name, bytes } or as a { name: bytes } record; anything else yields no section.
 */
export function readManifestSections(bundle: DiagnosticBundle): DiagnosticSectionInfo[] {
  const raw: unknown = bundle.manifest?.sections;
  if (Array.isArray(raw)) {
    return raw
      .filter(
        (s): s is DiagnosticSectionInfo =>
          typeof s === 'object' &&
          s !== null &&
          typeof (s as DiagnosticSectionInfo).name === 'string' &&
          typeof (s as DiagnosticSectionInfo).bytes === 'number'
      )
      .map((s) => ({ name: s.name, bytes: s.bytes }));
  }
  if (typeof raw === 'object' && raw !== null) {
    return Object.entries(raw as Record<string, unknown>)
      .filter(([, bytes]) => typeof bytes === 'number')
      .map(([name, bytes]) => ({ name, bytes: bytes as number }));
  }
  return [];
}

/** Name of the downloaded file: the prefix, the local date and time, and the extension. */
export function buildDiagnosticFileName(now: Date): string {
  const pad = (n: number) => String(n).padStart(DATE_PAD, '0');
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(
    now.getHours()
  )}${pad(now.getMinutes())}`;
  return `${UI_CONFIG.DIAGNOSTIC_FILE_PREFIX}${stamp}.json`;
}
