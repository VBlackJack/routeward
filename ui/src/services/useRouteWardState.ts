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

import { useSyncExternalStore } from 'react';
import {
  FakeIpEntry,
  LogEntry,
  ProfileConfig,
  SystemDiagnostics,
  TelemetrySnapshot,
  TrackedConnection
} from '../types/routeward';
import { routewardClient } from './ipc';

const subscribeRouteWardClient = (listener: () => void): (() => void) =>
  routewardClient.subscribe(listener);

const getProfileSnapshot = (): ProfileConfig => routewardClient.getProfile();
const getDiagnosticsSnapshot = (): SystemDiagnostics =>
  routewardClient.getDiagnostics();
const getTelemetrySnapshot = (): TelemetrySnapshot =>
  routewardClient.getTelemetry();
const getConnectionsSnapshot = (): TrackedConnection[] =>
  routewardClient.listConnections();
const getFakeIpsSnapshot = (): FakeIpEntry[] => routewardClient.listFakeIps();
const getLogsSnapshot = (): LogEntry[] => routewardClient.listLogs();

export function useRouteWardProfile(): ProfileConfig {
  return useSyncExternalStore(subscribeRouteWardClient, getProfileSnapshot);
}

export function useRouteWardDiagnostics(): SystemDiagnostics {
  return useSyncExternalStore(subscribeRouteWardClient, getDiagnosticsSnapshot);
}

export function useRouteWardTelemetry(): TelemetrySnapshot {
  return useSyncExternalStore(subscribeRouteWardClient, getTelemetrySnapshot);
}

export function useRouteWardConnections(): TrackedConnection[] {
  return useSyncExternalStore(subscribeRouteWardClient, getConnectionsSnapshot);
}

export function useRouteWardFakeIps(): FakeIpEntry[] {
  return useSyncExternalStore(subscribeRouteWardClient, getFakeIpsSnapshot);
}

export function useRouteWardLogs(): LogEntry[] {
  return useSyncExternalStore(subscribeRouteWardClient, getLogsSnapshot);
}
