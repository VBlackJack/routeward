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

// Runs `npm audit` and fails on any advisory at or above the configured severity,
// except the advisories listed by name in audit-exceptions.json. An exception whose
// review date has passed fails the audit, so it cannot silently become permanent.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SEVERITY_ORDER = ['info', 'low', 'moderate', 'high', 'critical'];
const EXCEPTIONS_FILE = 'audit-exceptions.json';
const ADVISORY_ID_PATTERN = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;

const uiRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(readFileSync(join(uiRoot, EXCEPTIONS_FILE), 'utf8'));
const minimumRank = SEVERITY_ORDER.indexOf(config.minimumSeverity);
if (minimumRank < 0) {
  console.error(`Unknown minimumSeverity "${config.minimumSeverity}" in ${EXCEPTIONS_FILE}`);
  process.exit(2);
}

const today = new Date().toISOString().slice(0, 10);
const expired = config.exceptions.filter((entry) => entry.reviewBy < today);
for (const entry of expired) {
  console.error(`Audit exception ${entry.advisory} passed its review date ${entry.reviewBy}: re-check it or remove it.`);
}

let rawReport;
try {
  rawReport = execFileSync('npm', ['audit', '--json'], {
    cwd: uiRoot,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    stdio: ['ignore', 'pipe', 'inherit'],
  });
} catch (error) {
  // npm audit exits non-zero whenever it finds anything; the JSON report is still on stdout.
  rawReport = error.stdout;
}
if (!rawReport) {
  console.error('npm audit produced no report');
  process.exit(2);
}

const report = JSON.parse(rawReport);
const ignored = new Set(config.exceptions.map((entry) => entry.advisory.toUpperCase()));
const advisories = new Map();
for (const vulnerability of Object.values(report.vulnerabilities ?? {})) {
  for (const via of vulnerability.via) {
    if (typeof via !== 'object' || SEVERITY_ORDER.indexOf(via.severity) < minimumRank) {
      continue;
    }
    const id = (via.url?.match(ADVISORY_ID_PATTERN)?.[0] ?? String(via.source)).toUpperCase();
    advisories.set(id, via);
  }
}

const blocking = [...advisories].filter(([id]) => !ignored.has(id));
for (const [id] of advisories) {
  if (ignored.has(id)) {
    console.log(`Ignored by ${EXCEPTIONS_FILE}: ${id}`);
  }
}
for (const [id, via] of blocking) {
  console.error(`${via.severity}: ${via.name} ${via.range} ${id} ${via.title}`);
}

if (blocking.length > 0 || expired.length > 0) {
  process.exit(1);
}
console.log(`No unexcepted advisory at or above ${config.minimumSeverity}.`);
