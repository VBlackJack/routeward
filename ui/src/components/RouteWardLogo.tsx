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

import React, { useState } from 'react';

interface RouteWardLogoProps {
  size?: 'sm' | 'md';
}

export const RouteWardLogo: React.FC<RouteWardLogoProps> = ({
  size = 'md'
}) => {
  const [imgError, setImgError] = useState(false);
  const dim = size === 'sm' ? 'h-6 w-6' : 'h-10 w-10';

  return (
    <div
      className={`relative flex ${dim} shrink-0 items-center justify-center`}
    >
      {!imgError ? (
        <img
          src="/routeward-glyph.svg"
          alt="RouteWard"
          onError={() => setImgError(true)}
          className="h-full w-full object-contain"
        />
      ) : (
        <svg
          viewBox="0 0 64 64"
          className="h-full w-full"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <polygon
            points="32,6 55,19 55,45 32,58 9,45 9,19"
            fill="#1E202E"
            stroke="#BD93F9"
            strokeWidth="3.5"
            strokeLinejoin="round"
          />
          <polygon
            points="32,8 32,56 11,44 11,20"
            fill="#2B2E42"
            opacity="0.65"
          />
          <path
            d="M17 32 H29 L40 21 H46"
            stroke="#50FA7B"
            strokeWidth="4.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M42 16 L48 21 L42 26"
            stroke="#50FA7B"
            strokeWidth="4.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M29 32 L39 42 H46"
            stroke="#8BE9FD"
            strokeWidth="3.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            opacity="0.9"
          />
          <circle cx="17" cy="32" r="3.2" fill="#F8F8F2" />
        </svg>
      )}
    </div>
  );
};
