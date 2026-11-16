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
import { act, cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { THEMEFORGE_CATALOG_DATA, UI_CONFIG } from '../config/constants';
import { routewardClient } from '../services/ipc';
import { ThemeForgePalette } from '../types/routeward';
import {
  isValidThemePalette,
  ThemeForgeProvider,
  useThemeForge
} from './ThemeForgeContext';

const builtIn = THEMEFORGE_CATALOG_DATA.palettes as ThemeForgePalette[];
const requiredSlots = Object.keys(builtIn[0].colors);

function customPalette(
  overrides: Partial<ThemeForgePalette['colors']> = {}
): ThemeForgePalette {
  return {
    ...builtIn[0],
    name: 'CustomTest',
    displayName: 'Custom Test',
    colors: { ...builtIn[0].colors, ...overrides }
  };
}

describe('ThemeForge palette validation', () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.spyOn(routewardClient, 'setDesktopTheme').mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('accepts a complete palette and rejects missing or malformed color slots', () => {
    expect(isValidThemePalette(customPalette(), requiredSlots)).toBe(true);
    expect(
      isValidThemePalette(
        { ...customPalette(), colors: { ...builtIn[0].colors, Surface: undefined } },
        requiredSlots
      )
    ).toBe(false);
    expect(
      isValidThemePalette(customPalette({ Border: 'not-a-color' }), requiredSlots)
    ).toBe(false);
    expect(
      isValidThemePalette(customPalette({ Accent: '#12345' }), requiredSlots)
    ).toBe(false);
    expect(isValidThemePalette({ ...customPalette(), version: 2 }, requiredSlots)).toBe(
      false
    );
    expect(isValidThemePalette(null, requiredSlots)).toBe(false);
  });

  it('refuses to import a palette without a Surface slot and does not persist it', () => {
    let importer: ((json: string) => boolean) | null = null;
    const Probe: React.FC = () => {
      importer = useThemeForge().importExternalPalette;
      return null;
    };
    render(
      <ThemeForgeProvider>
        <Probe />
      </ThemeForgeProvider>
    );

    const broken = customPalette();
    const brokenColors: Record<string, string> = { ...broken.colors };
    delete brokenColors.Surface;
    let accepted = true;
    act(() => {
      accepted = importer!(
        JSON.stringify({ ...broken, colors: brokenColors })
      );
    });
    expect(accepted).toBe(false);
    expect(
      window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.CUSTOM_PALETTES)
    ).toBeNull();

    act(() => {
      accepted = importer!(JSON.stringify(customPalette()));
    });
    expect(accepted).toBe(true);
    expect(
      window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.CUSTOM_PALETTES)
    ).toContain('CustomTest');
  });

  it('falls back to the default palette when a stored custom palette is invalid', () => {
    const broken = customPalette();
    const brokenColors: Record<string, string> = { ...broken.colors };
    delete brokenColors.Surface;
    window.localStorage.setItem(
      UI_CONFIG.STORAGE_KEYS.CUSTOM_PALETTES,
      JSON.stringify([{ ...broken, colors: brokenColors }])
    );
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.THEME, 'CustomTest');

    let activeName = '';
    const Probe: React.FC = () => {
      activeName = useThemeForge().activePalette.name;
      return null;
    };
    render(
      <ThemeForgeProvider>
        <Probe />
      </ThemeForgeProvider>
    );
    expect(activeName).toBe(builtIn[0].name);

    cleanup();
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.CUSTOM_PALETTES, '{not json');
    render(
      <ThemeForgeProvider>
        <Probe />
      </ThemeForgeProvider>
    );
    expect(activeName).toBe(builtIn[0].name);
  });

  it('keeps every built-in palette valid and Dracula secondary text above 4.5:1 contrast', () => {
    for (const palette of builtIn) {
      expect(isValidThemePalette(palette, requiredSlots)).toBe(true);
    }
    const dracula = builtIn.find((p) => p.name === 'Dracula');
    expect(dracula).toBeDefined();
    const luminance = (hex: string): number => {
      const rgb = hex
        .slice(-6)
        .match(/../g)!
        .map((c) => parseInt(c, 16) / 255)
        .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
      return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
    };
    const ratio = (a: string, b: string): number => {
      const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
      return (hi + 0.05) / (lo + 0.05);
    };
    const colors = dracula!.colors;
    expect(ratio(colors.TextSecondary, colors.Background)).toBeGreaterThanOrEqual(4.5);
    expect(ratio(colors.TextSecondary, colors.Surface)).toBeGreaterThanOrEqual(4.5);
  });
});
