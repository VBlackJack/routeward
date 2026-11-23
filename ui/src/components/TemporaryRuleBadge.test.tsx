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

import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import i18n from '../i18n';
import { TemporaryRuleBadge } from './TemporaryRuleBadge';

describe('TemporaryRuleBadge', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('en');
  });
  afterEach(() => cleanup());

  it('shows the time left for a rule that expires', () => {
    const expiresAt = new Date(Date.now() + 14 * 60_000 + 30_000).toISOString();
    render(<TemporaryRuleBadge expiresAt={expiresAt} />);
    const badge = screen.getByTestId('temporary-rule-badge');
    expect(badge).toHaveTextContent(
      i18n.t('rules.temporary.badge', { time: i18n.t('rules.temporary.minutes', { count: 15 }) })
    );
  });

  it('shows hours and minutes for a longer exception', () => {
    const expiresAt = new Date(Date.now() + 59 * 60_000 + 60_000 + 5 * 60_000).toISOString();
    render(<TemporaryRuleBadge expiresAt={expiresAt} />);
    expect(screen.getByTestId('temporary-rule-badge')).toHaveTextContent(
      i18n.t('rules.temporary.hours_minutes', { hours: 1, minutes: 5 })
    );
  });

  it('renders nothing for a permanent or an already expired rule', () => {
    const { rerender } = render(<TemporaryRuleBadge expiresAt={null} />);
    expect(screen.queryByTestId('temporary-rule-badge')).not.toBeInTheDocument();
    rerender(<TemporaryRuleBadge expiresAt={new Date(Date.now() - 1000).toISOString()} />);
    expect(screen.queryByTestId('temporary-rule-badge')).not.toBeInTheDocument();
  });
});
