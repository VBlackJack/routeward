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

import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { THEMEFORGE_CATALOG_DATA, UI_CONFIG } from '../config/constants';
import { routewardClient } from '../services/ipc';
import {
  AccentTint,
  ThemeForgeColors,
  ThemeForgePalette
} from '../types/routeward';

interface ThemeForgeContextValue {
  palettes: ThemeForgePalette[];
  accents: AccentTint[];
  activeThemeName: string;
  activeAccent: AccentTint;
  activePalette: ThemeForgePalette;
  effectiveColors: ThemeForgeColors;
  setTheme: (themeName: string) => void;
  setAccent: (accent: AccentTint) => void;
  importExternalPalette: (jsonText: string) => boolean;
}

const ThemeForgeContext = createContext<ThemeForgeContextValue | null>(null);

const HEX_BASE = 16;
const MAX_CHANNEL = 255;
const HEX_COLOR_PATTERN = /^#(?:[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$/;
const SUPPORTED_PALETTE_VERSION = 1;

/**
 * Returns true when `value` is a usable palette: supported version, a name, and a valid hex
 * string for every color slot listed in `requiredSlots`.
 */
export function isValidThemePalette(
  value: unknown,
  requiredSlots: readonly string[]
): value is ThemeForgePalette {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Partial<ThemeForgePalette>;
  if (
    candidate.version !== SUPPORTED_PALETTE_VERSION ||
    typeof candidate.name !== 'string' ||
    !candidate.name.trim() ||
    !candidate.colors ||
    typeof candidate.colors !== 'object'
  ) {
    return false;
  }
  const colors = candidate.colors as unknown as Record<string, unknown>;
  return requiredSlots.every((slot) => {
    const slotValue = colors[slot];
    return typeof slotValue === 'string' && HEX_COLOR_PATTERN.test(slotValue);
  });
}

function shiftHexColor(hex: string, delta: number): string {
  const clean = hex.replace('#', '');
  const rgbHex = clean.length === 8 ? clean.slice(2) : clean;
  if (rgbHex.length !== 6) {
    return hex;
  }
  const r = Math.min(
    MAX_CHANNEL,
    Math.max(0, parseInt(rgbHex.slice(0, 2), HEX_BASE) + delta)
  );
  const g = Math.min(
    MAX_CHANNEL,
    Math.max(0, parseInt(rgbHex.slice(2, 4), HEX_BASE) + delta)
  );
  const b = Math.min(
    MAX_CHANNEL,
    Math.max(0, parseInt(rgbHex.slice(4, 6), HEX_BASE) + delta)
  );
  return `#${[r, g, b]
    .map((c) => c.toString(HEX_BASE).padStart(2, '0'))
    .join('')
    .toUpperCase()}`;
}

function normalizeHex(hex: string): string {
  const clean = hex.replace('#', '');
  if (clean.length === 8) {
    return `#${clean.slice(2)}`;
  }
  return hex;
}

export const ThemeForgeProvider: React.FC<{ children: React.ReactNode }> = ({
  children
}) => {
  const builtInPalettes = THEMEFORGE_CATALOG_DATA.palettes as ThemeForgePalette[];
  const accents = THEMEFORGE_CATALOG_DATA.accents as AccentTint[];
  const requiredColorSlots = Object.keys(builtInPalettes[0].colors);

  const [customPalettes, setCustomPalettes] = useState<ThemeForgePalette[]>(() => {
    try {
      const raw = window.localStorage.getItem(
        UI_CONFIG.STORAGE_KEYS.CUSTOM_PALETTES
      );
      const stored: unknown = raw ? JSON.parse(raw) : [];
      // A stored palette that fails validation is dropped so it cannot break the UI at startup.
      return Array.isArray(stored)
        ? stored.filter((p): p is ThemeForgePalette =>
            isValidThemePalette(p, requiredColorSlots)
          )
        : [];
    } catch {
      return [];
    }
  });

  const [activeThemeName, setActiveThemeName] = useState<string>(() => {
    return (
      window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.THEME) ||
      THEMEFORGE_CATALOG_DATA.defaultTheme
    );
  });

  const [activeAccent, setActiveAccent] = useState<AccentTint>(() => {
    return (
      (window.localStorage.getItem(UI_CONFIG.STORAGE_KEYS.ACCENT) as AccentTint) ||
      (THEMEFORGE_CATALOG_DATA.defaultAccent as AccentTint)
    );
  });

  const palettes = useMemo(
    () => [...builtInPalettes, ...customPalettes],
    [builtInPalettes, customPalettes]
  );

  const activePalette = useMemo(() => {
    return (
      palettes.find((p) => p.name === activeThemeName) || builtInPalettes[0]
    );
  }, [palettes, activeThemeName, builtInPalettes]);

  const effectiveColors = useMemo<ThemeForgeColors>(() => {
    const base = activePalette.colors;
    if (activeAccent === 'Default') {
      return base;
    }
    const chosenAccentHex = normalizeHex(base[activeAccent] || base.Accent);
    const hoverDelta = activePalette.isLight
      ? -UI_CONFIG.ACCENT_HOVER_LIGHTNESS_DELTA
      : UI_CONFIG.ACCENT_HOVER_LIGHTNESS_DELTA;
    const pressedDelta = activePalette.isLight
      ? -UI_CONFIG.ACCENT_PRESSED_LIGHTNESS_DELTA
      : UI_CONFIG.ACCENT_PRESSED_LIGHTNESS_DELTA;

    return {
      ...base,
      Accent: chosenAccentHex,
      AccentHover: shiftHexColor(chosenAccentHex, hoverDelta),
      AccentPressed: shiftHexColor(chosenAccentHex, pressedDelta)
    };
  }, [activePalette, activeAccent]);

  useEffect(() => {
    const root = document.documentElement;
    (Object.keys(effectiveColors) as Array<keyof ThemeForgeColors>).forEach(
      (slot) => {
        root.style.setProperty(
          `--tf-${slot}`,
          normalizeHex(effectiveColors[slot])
        );
      }
    );
    root.style.setProperty(
      '--tf-border-width',
      activePalette.isHighContrast
        ? UI_CONFIG.HIGH_CONTRAST_BORDER_PX
        : UI_CONFIG.STANDARD_BORDER_PX
    );
    root.style.colorScheme = Boolean(activePalette.isLight) ? 'light' : 'dark';
    void routewardClient
      .setDesktopTheme({
      theme: activePalette.name,
      accent: activeAccent,
      isLight: Boolean(activePalette.isLight),
      surfaceHex: normalizeHex(effectiveColors.Surface),
      textPrimaryHex: normalizeHex(effectiveColors.TextPrimary),
      borderHex: normalizeHex(effectiveColors.Border)
    }).catch(() => {
      // Window chrome theming is cosmetic; a bridge rejection must not break the UI
    });
  }, [effectiveColors, activePalette, activeAccent]);

  const setTheme = (themeName: string) => {
    setActiveThemeName(themeName);
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.THEME, themeName);
  };

  const setAccent = (accent: AccentTint) => {
    setActiveAccent(accent);
    window.localStorage.setItem(UI_CONFIG.STORAGE_KEYS.ACCENT, accent);
  };

  const importExternalPalette = (jsonText: string): boolean => {
    try {
      const raw: unknown = JSON.parse(jsonText);
      if (!isValidThemePalette(raw, requiredColorSlots)) {
        return false;
      }
      const parsed: ThemeForgePalette = {
        ...raw,
        displayName:
          typeof raw.displayName === 'string' && raw.displayName.trim()
            ? raw.displayName
            : raw.name
      };
      const next = [
        ...customPalettes.filter((p) => p.name !== parsed.name),
        parsed
      ];
      setCustomPalettes(next);
      window.localStorage.setItem(
        UI_CONFIG.STORAGE_KEYS.CUSTOM_PALETTES,
        JSON.stringify(next)
      );
      setTheme(parsed.name);
      return true;
    } catch {
      return false;
    }
  };

  return (
    <ThemeForgeContext.Provider
      value={{
        palettes,
        accents,
        activeThemeName,
        activeAccent,
        activePalette,
        effectiveColors,
        setTheme,
        setAccent,
        importExternalPalette
      }}
    >
      {children}
    </ThemeForgeContext.Provider>
  );
};

export function useThemeForge(): ThemeForgeContextValue {
  const ctx = useContext(ThemeForgeContext);
  if (!ctx) {
    throw new Error('useThemeForge must be used within a ThemeForgeProvider');
  }
  return ctx;
}
