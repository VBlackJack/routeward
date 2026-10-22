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
      className={`relative flex ${dim} shrink-0 items-center justify-center overflow-hidden rounded-tf-lg border border-tf-accent/50 bg-tf-bg shadow-md`}
    >
      {!imgError ? (
        <img
          src="/logo.jpg"
          alt="RouteWard"
          onError={() => setImgError(true)}
          className="h-full w-full object-cover"
        />
      ) : (
        <svg
          viewBox="0 0 32 32"
          className="h-full w-full p-1"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <polygon
            points="10,2 22,2 30,10 30,22 22,30 10,30 2,22 2,10"
            className="fill-tf-surface stroke-tf-accent"
            strokeWidth="2"
          />
          <path
            d="M7 16H14L24 9M14 16L24 16M14 16L24 23"
            className="stroke-tf-cyan"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <circle cx="14" cy="16" r="3" className="fill-tf-accent" />
          <circle cx="24" cy="9" r="2" className="fill-tf-pink" />
          <circle cx="24" cy="16" r="2" className="fill-tf-cyan" />
          <circle cx="24" cy="23" r="2" className="fill-tf-green" />
        </svg>
      )}
    </div>
  );
};
