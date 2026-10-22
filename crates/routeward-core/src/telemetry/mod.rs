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

use crate::config::{TelemetryConstants, TransportProtocol};
use crate::logger::FileLogger;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Active,
    Closed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedConnection {
    pub id: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub target_host: String,
    pub resolved_domain: Option<String>,
    pub target_port: u16,
    pub protocol: TransportProtocol,
    pub matched_rule: String,
    pub route_label: String,
    pub latency_ms: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub status: ConnectionStatus,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BandwidthSample {
    pub timestamp: String,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTrafficSummary {
    pub process_name: String,
    pub active_sockets: usize,
    pub total_connections: usize,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetrySnapshot {
    pub active_connections: usize,
    pub download_bytes_per_sec: u64,
    pub upload_bytes_per_sec: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub proxied_count: u64,
    pub direct_count: u64,
    pub blocked_count: u64,
    pub bandwidth_history: Vec<BandwidthSample>,
    pub top_talkers: Vec<ProcessTrafficSummary>,
}

#[derive(Clone)]
pub struct TelemetryHub {
    connections: Arc<DashMap<String, TrackedConnection>>,
    logs: Arc<RwLock<VecDeque<LogEntry>>>,
    bandwidth_history: Arc<RwLock<VecDeque<BandwidthSample>>>,
    file_logger: FileLogger,
    max_logs: usize,
    max_samples: usize,
    total_rx: Arc<AtomicU64>,
    total_tx: Arc<AtomicU64>,
    window_rx: Arc<AtomicU64>,
    window_tx: Arc<AtomicU64>,
    proxied_count: Arc<AtomicU64>,
    direct_count: Arc<AtomicU64>,
    blocked_count: Arc<AtomicU64>,
}

impl TelemetryHub {
    pub fn new(constants: &TelemetryConstants) -> Self {
        let file_logger = FileLogger::new(&constants.log_directory, &constants.log_app_name, true);
        Self {
            connections: Arc::new(DashMap::new()),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(
                constants.max_log_ring_buffer_entries,
            ))),
            bandwidth_history: Arc::new(RwLock::new(VecDeque::with_capacity(
                constants.max_bandwidth_history_samples,
            ))),
            file_logger,
            max_logs: constants.max_log_ring_buffer_entries,
            max_samples: constants.max_bandwidth_history_samples,
            total_rx: Arc::new(AtomicU64::new(0)),
            total_tx: Arc::new(AtomicU64::new(0)),
            window_rx: Arc::new(AtomicU64::new(0)),
            window_tx: Arc::new(AtomicU64::new(0)),
            proxied_count: Arc::new(AtomicU64::new(0)),
            direct_count: Arc::new(AtomicU64::new(0)),
            blocked_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_file_logging_enabled(&self, enabled: bool) {
        self.file_logger.set_enabled(enabled);
    }

    pub fn flush_file_logger(&self) {
        self.file_logger.flush();
    }

    pub fn record_connection(&self, conn: TrackedConnection, is_proxied: bool) {
        match conn.status {
            ConnectionStatus::Blocked => {
                self.blocked_count.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                if is_proxied {
                    self.proxied_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.direct_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.add_traffic(conn.rx_bytes, conn.tx_bytes);
        self.connections.insert(conn.id.clone(), conn);
    }

    pub fn update_connection_traffic(&self, id: &str, delta_rx: u64, delta_tx: u64) {
        if let Some(mut entry) = self.connections.get_mut(id) {
            entry.rx_bytes += delta_rx;
            entry.tx_bytes += delta_tx;
        }
        self.add_traffic(delta_rx, delta_tx);
    }

    pub fn mark_connection_closed(&self, id: &str) {
        if let Some(mut entry) = self.connections.get_mut(id) {
            entry.status = ConnectionStatus::Closed;
        }
    }

    pub fn clear_closed_connections(&self) {
        let closed_ids: Vec<String> = self
            .connections
            .iter()
            .filter(|c| c.value().status != ConnectionStatus::Active)
            .map(|c| c.key().clone())
            .collect();
        for id in closed_ids {
            self.connections.remove(&id);
        }
    }

    pub fn list_connections(&self) -> Vec<TrackedConnection> {
        let mut list: Vec<TrackedConnection> =
            self.connections.iter().map(|c| c.value().clone()).collect();
        list.sort_by_key(|b| std::cmp::Reverse(b.started_at));
        list
    }

    pub fn add_traffic(&self, rx: u64, tx: u64) {
        if rx > 0 {
            self.total_rx.fetch_add(rx, Ordering::Relaxed);
            self.window_rx.fetch_add(rx, Ordering::Relaxed);
        }
        if tx > 0 {
            self.total_tx.fetch_add(tx, Ordering::Relaxed);
            self.window_tx.fetch_add(tx, Ordering::Relaxed);
        }
    }

    pub fn tick_bandwidth_sample(&self) {
        let rx_sec = self.window_rx.swap(0, Ordering::Relaxed);
        let tx_sec = self.window_tx.swap(0, Ordering::Relaxed);
        let timestamp = Utc::now().format("%H:%M:%S").to_string();

        let mut hist = self.bandwidth_history.write();
        if hist.len() >= self.max_samples {
            hist.pop_front();
        }
        hist.push_back(BandwidthSample {
            timestamp,
            rx_bytes_per_sec: rx_sec,
            tx_bytes_per_sec: tx_sec,
        });
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let active_connections = self
            .connections
            .iter()
            .filter(|c| c.value().status == ConnectionStatus::Active)
            .count();

        let hist = self.bandwidth_history.read();
        let last_sample = hist.back();
        let download_bytes_per_sec = last_sample.map(|s| s.rx_bytes_per_sec).unwrap_or(0);
        let upload_bytes_per_sec = last_sample.map(|s| s.tx_bytes_per_sec).unwrap_or(0);

        TelemetrySnapshot {
            active_connections,
            download_bytes_per_sec,
            upload_bytes_per_sec,
            total_rx_bytes: self.total_rx.load(Ordering::Relaxed),
            total_tx_bytes: self.total_tx.load(Ordering::Relaxed),
            proxied_count: self.proxied_count.load(Ordering::Relaxed),
            direct_count: self.direct_count.load(Ordering::Relaxed),
            blocked_count: self.blocked_count.load(Ordering::Relaxed),
            bandwidth_history: hist.iter().cloned().collect(),
            top_talkers: self.compute_top_talkers(),
        }
    }

    pub fn compute_top_talkers(&self) -> Vec<ProcessTrafficSummary> {
        use std::collections::HashMap;
        let mut map: HashMap<String, ProcessTrafficSummary> = HashMap::new();
        for item in self.connections.iter() {
            let conn = item.value();
            let entry =
                map.entry(conn.process_name.clone())
                    .or_insert_with(|| ProcessTrafficSummary {
                        process_name: conn.process_name.clone(),
                        active_sockets: 0,
                        total_connections: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                    });
            entry.total_connections += 1;
            if conn.status == ConnectionStatus::Active {
                entry.active_sockets += 1;
            }
            entry.rx_bytes += conn.rx_bytes;
            entry.tx_bytes += conn.tx_bytes;
        }
        let mut list: Vec<ProcessTrafficSummary> = map.into_values().collect();
        list.sort_by_key(|b| std::cmp::Reverse(b.rx_bytes + b.tx_bytes));
        list
    }

    pub fn push_log(&self, level: LogLevel, component: &str, message: impl Into<String>) {
        let msg = message.into();
        self.file_logger.log(level, component, &msg);
        let mut logs = self.logs.write();
        if logs.len() >= self.max_logs {
            logs.pop_front();
        }
        logs.push_back(LogEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            level,
            component: component.to_string(),
            message: msg,
        });
    }

    pub fn list_logs(&self) -> Vec<LogEntry> {
        let logs = self.logs.read();
        let mut vec: Vec<LogEntry> = logs.iter().cloned().collect();
        vec.reverse();
        vec
    }

    pub fn clear_logs(&self) {
        self.logs.write().clear();
    }
}
