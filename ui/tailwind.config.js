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

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        tf: {
          bg: 'var(--tf-Background)',
          line: 'var(--tf-CurrentLine)',
          selection: 'var(--tf-Selection)',
          fg: 'var(--tf-Foreground)',
          comment: 'var(--tf-Comment)',
          surface: 'var(--tf-Surface)',
          'surface-alt': 'var(--tf-SurfaceAlt)',
          accent: 'var(--tf-Accent)',
          'accent-hover': 'var(--tf-AccentHover)',
          'accent-pressed': 'var(--tf-AccentPressed)',
          primary: 'var(--tf-TextPrimary)',
          secondary: 'var(--tf-TextSecondary)',
          border: 'var(--tf-Border)',
          success: 'var(--tf-Success)',
          warning: 'var(--tf-Warning)',
          error: 'var(--tf-Error)',
          info: 'var(--tf-Info)',
          blue: 'var(--tf-Blue)',
          cyan: 'var(--tf-Cyan)',
          green: 'var(--tf-Green)',
          orange: 'var(--tf-Orange)',
          pink: 'var(--tf-Pink)',
          purple: 'var(--tf-Purple)',
          red: 'var(--tf-Red)',
          yellow: 'var(--tf-Yellow)'
        }
      },
      borderRadius: {
        'tf-xs': 'var(--tf-radius-xs)',
        'tf-sm': 'var(--tf-radius-sm)',
        'tf-md': 'var(--tf-radius-md)',
        'tf-lg': 'var(--tf-radius-lg)',
        'tf-xl': 'var(--tf-radius-xl)'
      }
    }
  },
  plugins: []
};
