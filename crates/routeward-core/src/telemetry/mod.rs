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
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{broadcast, watch};
use uuid::Uuid;

const MIN_BROADCAST_CAPACITY: usize = 16;

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
    Debug,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
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

impl LogEntry {
    pub fn new(level: LogLevel, component: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            level,
            component: component.into(),
            message: message.into(),
        }
    }
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

/// Real-time event broadcast by [`TelemetryHub`] to subscribers (for example IPC / UI streams).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
pub enum TelemetryEvent {
    Telemetry(TelemetrySnapshot),
    ConnectionUpdated(TrackedConnection),
    ConnectionsCleared,
    Log(LogEntry),
    LogsCleared,
}

/// Async stream wrapper that increments `rx_bytes` (reads from upstream) and `tx_bytes`
/// (writes to upstream) in [`TelemetryHub`] continuously as chunks flow through the tunnel.
pub struct TelemetryCountingStream<'a, S> {
    inner: &'a mut S,
    connection_id: String,
    telemetry: TelemetryHub,
}

impl<'a, S> TelemetryCountingStream<'a, S> {
    pub fn new(inner: &'a mut S, connection_id: String, telemetry: TelemetryHub) -> Self {
        Self {
            inner,
            connection_id,
            telemetry,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TelemetryCountingStream<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let delta_rx = buf.filled().len().saturating_sub(before);
            if delta_rx > 0 {
                self.telemetry
                    .update_connection_traffic(&self.connection_id, delta_rx as u64, 0);
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TelemetryCountingStream<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &poll {
            if *written > 0 {
                self.telemetry
                    .update_connection_traffic(&self.connection_id, 0, *written as u64);
            }
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// A tracked connection together with the bookkeeping that throttles its `ConnectionUpdated` events.
struct ConnectionSlot {
    conn: TrackedConnection,
    /// When a `ConnectionUpdated` event was last broadcast for this connection.
    last_emit: Instant,
    /// Counters changed since the last broadcast.
    dirty: bool,
}

/// Non-active connection ids ordered by start time, oldest first.
type EvictionIndex = BTreeSet<(DateTime<Utc>, String)>;

/// One aggregated UDP flow: all datagrams of a (protocol, 5-tuple, route) share one record.
struct UdpFlow {
    conn_id: String,
    last_seen: Instant,
}

/// Builds the aggregation key of a UDP flow: transport, client endpoint, target endpoint and route.
pub fn udp_flow_key(client: SocketAddr, target: SocketAddr, route_label: &str) -> String {
    format!("udp|{client}|{target}|{route_label}")
}

#[derive(Clone)]
pub struct TelemetryHub {
    connections: Arc<DashMap<String, ConnectionSlot>>,
    udp_flows: Arc<DashMap<String, UdpFlow>>,
    /// Non-active connections ordered oldest first: the only records eligible for eviction.
    evictable: Arc<Mutex<EvictionIndex>>,
    udp_flow_idle_timeout: Duration,
    update_interval: Duration,
    active_cancellers: Arc<DashMap<String, watch::Sender<bool>>>,
    logs: Arc<RwLock<VecDeque<LogEntry>>>,
    bandwidth_history: Arc<RwLock<VecDeque<BandwidthSample>>>,
    event_tx: broadcast::Sender<TelemetryEvent>,
    file_logger: FileLogger,
    max_logs: usize,
    max_connections: usize,
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
        Self::new_with_logging(constants, true)
    }

    pub fn new_with_logging(constants: &TelemetryConstants, enable_logging: bool) -> Self {
        Self::new_with_log_dir(
            constants,
            constants.resolve_daemon_log_dir(),
            enable_logging,
        )
    }

    pub fn new_with_log_dir(
        constants: &TelemetryConstants,
        log_dir: impl Into<std::path::PathBuf>,
        enable_logging: bool,
    ) -> Self {
        let file_logger = FileLogger::with_flush_interval(
            log_dir,
            &constants.log_app_name,
            enable_logging,
            constants.log_flush_interval_ms,
        );
        let broadcast_cap = constants
            .event_broadcast_capacity
            .max(MIN_BROADCAST_CAPACITY);
        let (event_tx, _) = broadcast::channel(broadcast_cap);

        Self {
            connections: Arc::new(DashMap::new()),
            udp_flows: Arc::new(DashMap::new()),
            evictable: Arc::new(Mutex::new(BTreeSet::new())),
            udp_flow_idle_timeout: Duration::from_millis(constants.udp_flow_idle_timeout_ms),
            update_interval: Duration::from_millis(constants.telemetry_update_interval_ms),
            active_cancellers: Arc::new(DashMap::new()),
            logs: Arc::new(RwLock::new(VecDeque::with_capacity(
                constants.max_log_ring_buffer_entries,
            ))),
            bandwidth_history: Arc::new(RwLock::new(VecDeque::with_capacity(
                constants.max_bandwidth_history_samples,
            ))),
            event_tx,
            file_logger,
            max_logs: constants.max_log_ring_buffer_entries,
            max_connections: constants.max_connection_history_entries.max(1),
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

    /// Subscribes to live [`TelemetryEvent`] notifications (telemetry ticks, connection updates, logs).
    pub fn subscribe(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.event_tx.subscribe()
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
        let evictable_key =
            (conn.status != ConnectionStatus::Active).then(|| (conn.started_at, conn.id.clone()));
        self.connections.insert(
            conn.id.clone(),
            ConnectionSlot {
                conn: conn.clone(),
                last_emit: Instant::now(),
                dirty: false,
            },
        );
        if let Some(key) = evictable_key {
            self.evictable.lock().insert(key);
        }
        self.evict_excess_connections();
        let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
    }

    /// Evicts the oldest non-active records (closed, blocked, idle UDP flows) while over capacity.
    /// Cost is proportional to the number of evicted records: no scan and no sort per insert.
    fn evict_excess_connections(&self) {
        if self.connections.len() <= self.max_connections {
            return;
        }
        let mut evictable = self.evictable.lock();
        while self.connections.len() > self.max_connections {
            let Some((_, id)) = evictable.pop_first() else {
                break;
            };
            self.connections.remove(&id);
        }
    }

    /// Adds `delta_rx` / `delta_tx` to a connection. The global counters move immediately; the
    /// `ConnectionUpdated` event is throttled to once per `telemetryUpdateIntervalMs` per
    /// connection (pending changes are flushed by [`Self::tick_bandwidth_sample`] and on close).
    pub fn update_connection_traffic(&self, id: &str, delta_rx: u64, delta_tx: u64) {
        self.add_traffic(delta_rx, delta_tx);
        let updated = if let Some(mut slot) = self.connections.get_mut(id) {
            slot.conn.rx_bytes += delta_rx;
            slot.conn.tx_bytes += delta_tx;
            slot.dirty = true;
            if slot.last_emit.elapsed() >= self.update_interval {
                slot.last_emit = Instant::now();
                slot.dirty = false;
                Some(slot.conn.clone())
            } else {
                None
            }
        } else {
            None
        };
        if let Some(conn) = updated {
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
        }
    }

    /// Broadcasts the connections whose counters changed since their last event and whose
    /// throttle interval has elapsed.
    fn flush_pending_connection_updates(&self) {
        let mut pending = Vec::new();
        for mut slot in self.connections.iter_mut() {
            if slot.dirty && slot.last_emit.elapsed() >= self.update_interval {
                slot.dirty = false;
                slot.last_emit = Instant::now();
                pending.push(slot.conn.clone());
            }
        }
        for conn in pending {
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
        }
    }

    pub fn mark_connection_closed(&self, id: &str) {
        self.active_cancellers.remove(id);
        let updated = if let Some(mut slot) = self.connections.get_mut(id) {
            slot.conn.status = ConnectionStatus::Closed;
            slot.dirty = false;
            slot.last_emit = Instant::now();
            Some(slot.conn.clone())
        } else {
            None
        };
        if let Some(conn) = updated {
            self.evictable
                .lock()
                .insert((conn.started_at, conn.id.clone()));
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
            self.evict_excess_connections();
        }
    }

    /// Records one UDP datagram of an aggregated flow. The first datagram of `flow_key` creates a
    /// single `Active` record from `template` (counters taken from `rx_bytes` / `tx_bytes`);
    /// later datagrams only update that record's traffic. Idle flows are closed by
    /// [`Self::sweep_idle_udp_flows`]. Returns `true` when this datagram started a new flow, so
    /// the caller logs the flow start once and the individual datagrams at debug level.
    ///
    /// `make_template` is only invoked for a new flow, so the hot per-datagram path allocates nothing.
    pub fn record_udp_datagram<F>(
        &self,
        flow_key: &str,
        make_template: F,
        is_proxied: bool,
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> bool
    where
        F: FnOnce() -> TrackedConnection,
    {
        if let Some(mut flow) = self.udp_flows.get_mut(flow_key) {
            flow.last_seen = Instant::now();
            let id = flow.conn_id.clone();
            drop(flow);
            let still_active = self
                .connections
                .get(&id)
                .is_some_and(|slot| slot.conn.status == ConnectionStatus::Active);
            if still_active {
                self.update_connection_traffic(&id, rx_bytes, tx_bytes);
                return false;
            }
            // The record was evicted, cleared or terminated: start a fresh one below.
            self.udp_flows.remove(flow_key);
        }
        if self.udp_flows.len() >= self.max_connections {
            self.sweep_idle_udp_flows();
            if self.udp_flows.len() >= self.max_connections {
                // Flow table saturated: keep the global byte counters honest but do not track
                // another record, so a port scan cannot grow telemetry without bound.
                self.add_traffic(rx_bytes, tx_bytes);
                return false;
            }
        }
        let mut template = make_template();
        template.status = ConnectionStatus::Active;
        template.rx_bytes = rx_bytes;
        template.tx_bytes = tx_bytes;
        self.udp_flows.insert(
            flow_key.to_string(),
            UdpFlow {
                conn_id: template.id.clone(),
                last_seen: Instant::now(),
            },
        );
        self.record_connection(template, is_proxied);
        true
    }

    /// Marks every UDP flow idle for longer than `udpFlowIdleTimeoutMs` as closed and forgets its
    /// flow key, so the record becomes evictable. Returns the number of closed flows.
    pub fn sweep_idle_udp_flows(&self) -> usize {
        let idle: Vec<(String, String)> = self
            .udp_flows
            .iter()
            .filter(|f| f.value().last_seen.elapsed() >= self.udp_flow_idle_timeout)
            .map(|f| (f.key().clone(), f.value().conn_id.clone()))
            .collect();
        for (flow_key, conn_id) in &idle {
            self.udp_flows.remove(flow_key);
            self.mark_connection_closed(conn_id);
        }
        idle.len()
    }

    /// Registers a cancellation watch channel for an active relayed connection.
    pub fn register_connection_cancellation(&self, id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        self.active_cancellers.insert(id.to_string(), tx);
        rx
    }

    /// Actively terminates an in-flight connection by signaling its relay task to abort and close sockets.
    pub fn terminate_connection(&self, id: &str) -> bool {
        let cancelled_live_tunnel = if let Some((_, tx)) = self.active_cancellers.remove(id) {
            let _ = tx.send(true);
            true
        } else {
            false
        };

        let updated = if let Some(mut slot) = self.connections.get_mut(id) {
            if slot.conn.status == ConnectionStatus::Active {
                slot.conn.status = ConnectionStatus::Closed;
                slot.dirty = false;
                slot.last_emit = Instant::now();
                Some(slot.conn.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(conn) = updated {
            self.evictable
                .lock()
                .insert((conn.started_at, conn.id.clone()));
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
            self.evict_excess_connections();
            return true;
        }

        cancelled_live_tunnel
    }

    /// Relays bidirectional traffic between `client` and `outbound` while updating `rx_bytes` and `tx_bytes`
    /// in real time on every chunk and honoring immediate cancellation via [`Self::terminate_connection`].
    pub async fn relay_bidirectional_with_telemetry<C, O>(
        &self,
        conn_id: &str,
        client: &mut C,
        outbound: &mut O,
    ) -> std::io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        O: AsyncRead + AsyncWrite + Unpin,
    {
        let mut cancel_rx = self.register_connection_cancellation(conn_id);
        let res = {
            let mut counted_outbound =
                TelemetryCountingStream::new(outbound, conn_id.to_string(), self.clone());
            tokio::select! {
                copy_res = tokio::io::copy_bidirectional(client, &mut counted_outbound) => {
                    copy_res.map(|_| ())
                }
                _ = cancel_rx.changed() => {
                    Ok(())
                }
            }
        };
        let _ = client.shutdown().await;
        let _ = outbound.shutdown().await;
        self.mark_connection_closed(conn_id);
        res
    }

    pub fn clear_closed_connections(&self) {
        let closed_ids: Vec<String> = self
            .connections
            .iter()
            .filter(|c| c.value().conn.status != ConnectionStatus::Active)
            .map(|c| c.key().clone())
            .collect();
        for id in closed_ids {
            self.connections.remove(&id);
        }
        self.evictable.lock().clear();
        let _ = self.event_tx.send(TelemetryEvent::ConnectionsCleared);
    }

    pub fn list_connections(&self) -> Vec<TrackedConnection> {
        let mut list: Vec<TrackedConnection> = self
            .connections
            .iter()
            .map(|c| c.value().conn.clone())
            .collect();
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

        {
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

        self.sweep_idle_udp_flows();
        self.flush_pending_connection_updates();
        let snap = self.snapshot();
        let _ = self.event_tx.send(TelemetryEvent::Telemetry(snap));
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let active_connections = self
            .connections
            .iter()
            .filter(|c| c.value().conn.status == ConnectionStatus::Active)
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
            let conn = &item.value().conn;
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
        if level == LogLevel::Debug {
            tracing::debug!(component = component, "{}", msg);
            return;
        }
        self.file_logger.log(level, component, &msg);
        let entry = LogEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            level,
            component: component.to_string(),
            message: msg,
        };
        {
            let mut logs = self.logs.write();
            if logs.len() >= self.max_logs {
                logs.pop_front();
            }
            logs.push_back(entry.clone());
        }
        let _ = self.event_tx.send(TelemetryEvent::Log(entry));
    }

    pub fn list_logs(&self) -> Vec<LogEntry> {
        let logs = self.logs.read();
        let mut vec: Vec<LogEntry> = logs.iter().cloned().collect();
        vec.reverse();
        vec
    }

    pub fn clear_logs(&self) {
        self.logs.write().clear();
        let _ = self.event_tx.send(TelemetryEvent::LogsCleared);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SystemConstants;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn streams_live_byte_counters_broadcasts_events_and_cancels_active_connection() {
        let constants = SystemConstants::load_embedded().expect("SystemConstants");
        let hub = TelemetryHub::new(&constants.telemetry);
        hub.set_file_logging_enabled(false);

        let mut rx_events = hub.subscribe();

        let conn_id = "conn-live-test-1".to_string();
        let tracked = TrackedConnection {
            id: conn_id.clone(),
            pid: 999,
            process_name: "curl".to_string(),
            process_path: "/usr/bin/curl".to_string(),
            target_host: "93.184.216.34".to_string(),
            resolved_domain: Some("example.com".to_string()),
            target_port: 443,
            protocol: TransportProtocol::Tcp,
            matched_rule: "Test Rule".to_string(),
            route_label: "Local SOCKS5".to_string(),
            latency_ms: 5,
            rx_bytes: 0,
            tx_bytes: 0,
            status: ConnectionStatus::Active,
            started_at: Utc::now(),
            error_detail: None,
        };
        hub.record_connection(tracked, true);

        // Verify initial ConnectionUpdated event
        match rx_events.recv().await.expect("event") {
            TelemetryEvent::ConnectionUpdated(c) => {
                assert_eq!(c.id, conn_id);
                assert_eq!(c.status, ConnectionStatus::Active);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let (mut client_app, mut relay_client_side) = tokio::io::duplex(4096);
        let (mut relay_outbound_side, mut remote_server) = tokio::io::duplex(4096);

        let hub_relay = hub.clone();
        let conn_id_relay = conn_id.clone();
        let relay_task = tokio::spawn(async move {
            hub_relay
                .relay_bidirectional_with_telemetry(
                    &conn_id_relay,
                    &mut relay_client_side,
                    &mut relay_outbound_side,
                )
                .await
        });

        // Send 12 bytes from client -> remote_server (upload / tx) while connection remains open
        client_app
            .write_all(b"HELLO_SERVER")
            .await
            .expect("client write");
        let mut server_buf = [0u8; 12];
        remote_server
            .read_exact(&mut server_buf)
            .await
            .expect("server read");
        assert_eq!(&server_buf, b"HELLO_SERVER");

        // Send 16 bytes from remote_server -> client (download / rx) while connection remains open
        remote_server
            .write_all(b"RESPONSE_PAYLOAD")
            .await
            .expect("server write");
        let mut client_buf = [0u8; 16];
        client_app
            .read_exact(&mut client_buf)
            .await
            .expect("client read");
        assert_eq!(&client_buf, b"RESPONSE_PAYLOAD");

        // While the tunnel is still open and active, verify live byte counters were updated!
        let snapshot_mid = hub.snapshot();
        assert_eq!(snapshot_mid.active_connections, 1);
        assert_eq!(snapshot_mid.total_tx_bytes, 12);
        assert_eq!(snapshot_mid.total_rx_bytes, 16);

        let live_conn = hub
            .list_connections()
            .into_iter()
            .find(|c| c.id == conn_id)
            .expect("tracked connection");
        assert_eq!(live_conn.status, ConnectionStatus::Active);
        assert_eq!(live_conn.tx_bytes, 12);
        assert_eq!(live_conn.rx_bytes, 16);

        // Tick bandwidth sample and verify Telemetry event is broadcast
        hub.tick_bandwidth_sample();
        let mut saw_telemetry_tick = false;
        while let Ok(ev) = rx_events.try_recv() {
            if let TelemetryEvent::Telemetry(snap) = ev {
                assert_eq!(snap.download_bytes_per_sec, 16);
                assert_eq!(snap.upload_bytes_per_sec, 12);
                saw_telemetry_tick = true;
            }
        }
        assert!(saw_telemetry_tick);

        // Now actively terminate the in-flight connection and verify the relay task exits immediately
        assert!(hub.terminate_connection(&conn_id));
        relay_task
            .await
            .expect("relay task joined")
            .expect("relay clean exit");

        let after_conn = hub
            .list_connections()
            .into_iter()
            .find(|c| c.id == conn_id)
            .expect("tracked connection after terminate");
        assert_eq!(after_conn.status, ConnectionStatus::Closed);
        assert_eq!(hub.snapshot().active_connections, 0);
    }

    #[test]
    fn evicts_oldest_inactive_connections_while_preserving_active_ones() {
        let constants = crate::config::TelemetryConstants {
            max_log_ring_buffer_entries: 16,
            max_connection_history_entries: 3,
            max_bandwidth_history_samples: 4,
            sampling_interval_ms: 1000,
            process_cache_ttl_ms: 1000,
            log_directory: "logs".to_string(),
            windows_daemon_log_dir: "%ProgramData%\\RouteWard\\logs".to_string(),
            linux_daemon_log_dir: "/var/log/routeward".to_string(),
            windows_user_log_dir: "%LOCALAPPDATA%\\RouteWard\\logs".to_string(),
            linux_user_log_dir: "$XDG_STATE_HOME/routeward/logs".to_string(),
            linux_user_fallback_log_dir: ".local/state/routeward/logs".to_string(),
            windows_user_webview_dir: "%LOCALAPPDATA%\\RouteWard\\WebView2".to_string(),
            linux_user_webview_dir: "$XDG_DATA_HOME/routeward/webview".to_string(),
            linux_user_fallback_webview_dir: ".local/share/routeward/webview".to_string(),
            log_app_name: "RouteWard".to_string(),
            log_flush_interval_ms: 500,
            event_broadcast_capacity: 16,
            udp_flow_idle_timeout_ms: 30000,
            telemetry_update_interval_ms: 250,
        };
        let hub = TelemetryHub::new_with_logging(&constants, false);
        let base_time = Utc::now();

        let make_conn = |id: &str, offset_secs: i64, status: ConnectionStatus| TrackedConnection {
            id: id.to_string(),
            pid: 42,
            process_name: "brave.exe".to_string(),
            process_path: String::new(),
            target_host: "example.com".to_string(),
            resolved_domain: Some("example.com".to_string()),
            target_port: 443,
            protocol: crate::config::TransportProtocol::Tcp,
            matched_rule: "rule-direct".to_string(),
            route_label: "DIRECT".to_string(),
            latency_ms: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            status,
            started_at: base_time + chrono::Duration::seconds(offset_secs),
            error_detail: None,
        };

        hub.record_connection(make_conn("active-old", 1, ConnectionStatus::Active), false);
        hub.record_connection(make_conn("closed-1", 2, ConnectionStatus::Closed), false);
        hub.record_connection(make_conn("blocked-2", 3, ConnectionStatus::Blocked), false);
        hub.record_connection(make_conn("closed-3", 4, ConnectionStatus::Closed), false);

        let ids: Vec<String> = hub.list_connections().into_iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"active-old".to_string()));
        assert!(!ids.contains(&"closed-1".to_string()));
        assert!(ids.contains(&"blocked-2".to_string()));
        assert!(ids.contains(&"closed-3".to_string()));
    }

    fn udp_template(id: &str) -> TrackedConnection {
        TrackedConnection {
            id: id.to_string(),
            pid: 7,
            process_name: "voip.exe".to_string(),
            process_path: String::new(),
            target_host: "203.0.113.9".to_string(),
            resolved_domain: None,
            target_port: 3478,
            protocol: TransportProtocol::Udp,
            matched_rule: "rule".to_string(),
            route_label: "DIRECT".to_string(),
            latency_ms: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            status: ConnectionStatus::Active,
            started_at: Utc::now(),
            error_detail: None,
        }
    }

    fn udp_test_hub(max_connections: usize, idle_ms: u64, update_ms: u64) -> TelemetryHub {
        let mut constants = SystemConstants::load_embedded()
            .expect("SystemConstants")
            .telemetry;
        constants.max_connection_history_entries = max_connections;
        constants.udp_flow_idle_timeout_ms = idle_ms;
        constants.telemetry_update_interval_ms = update_ms;
        TelemetryHub::new_with_logging(&constants, false)
    }

    fn udp_key(port: u16) -> String {
        udp_flow_key(
            format!("192.168.1.2:{port}").parse().unwrap(),
            "203.0.113.9:3478".parse().unwrap(),
            "DIRECT",
        )
    }

    #[test]
    fn udp_datagrams_of_one_flow_share_a_single_record() {
        let hub = udp_test_hub(500, 30_000, 250);
        let key = udp_key(50000);
        let mut started = 0;
        for i in 0..1000 {
            if hub.record_udp_datagram(&key, || udp_template(&format!("id-{i}")), false, 0, 100) {
                started += 1;
            }
        }
        assert_eq!(started, 1, "only the first datagram starts a flow");
        let conns = hub.list_connections();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].tx_bytes, 100_000);
        assert_eq!(conns[0].status, ConnectionStatus::Active);
        let snap = hub.snapshot();
        assert_eq!(snap.total_tx_bytes, 100_000);
        assert_eq!(snap.direct_count, 1);
    }

    #[test]
    fn idle_udp_flows_are_closed_and_become_evictable() {
        let hub = udp_test_hub(3, 20, 250);
        for port in 0..3u16 {
            hub.record_udp_datagram(
                &udp_key(50000 + port),
                || udp_template(&format!("f{port}")),
                false,
                0,
                10,
            );
        }
        assert_eq!(hub.snapshot().active_connections, 3);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(hub.sweep_idle_udp_flows(), 3);
        assert_eq!(hub.snapshot().active_connections, 0);

        // New flows push the closed (idle) records out instead of growing without bound.
        for port in 10..20u16 {
            hub.record_udp_datagram(
                &udp_key(50000 + port),
                || udp_template(&format!("g{port}")),
                false,
                0,
                10,
            );
        }
        assert!(hub.list_connections().len() <= 10);
        let ids: Vec<String> = hub.list_connections().into_iter().map(|c| c.id).collect();
        assert!(
            !ids.contains(&"f0".to_string()),
            "idle flow records were evicted"
        );

        // A datagram after the idle close starts a new flow record.
        std::thread::sleep(Duration::from_millis(60));
        assert!(hub.record_udp_datagram(&udp_key(50000), || udp_template("again"), false, 0, 10));
    }

    #[test]
    fn udp_flow_table_is_bounded_when_every_flow_is_still_active() {
        let hub = udp_test_hub(4, 60_000, 250);
        for port in 0..50u16 {
            hub.record_udp_datagram(
                &udp_key(40000 + port),
                || udp_template(&format!("h{port}")),
                false,
                0,
                10,
            );
        }
        assert!(hub.list_connections().len() <= 4);
        // Untracked flows still count towards the global byte totals.
        assert_eq!(hub.snapshot().total_tx_bytes, 500);
    }

    #[tokio::test]
    async fn connection_updates_are_throttled_and_flushed_on_tick_and_close() {
        let hub = udp_test_hub(500, 30_000, 10_000);
        let mut events = hub.subscribe();
        let mut conn = udp_template("t1");
        conn.protocol = TransportProtocol::Tcp;
        hub.record_connection(conn, true);
        for _ in 0..500 {
            hub.update_connection_traffic("t1", 10, 20);
        }
        // Only the record_connection event was emitted; 500 chunks did not broadcast 500 clones.
        let mut updates = 0;
        while let Ok(ev) = events.try_recv() {
            if matches!(ev, TelemetryEvent::ConnectionUpdated(_)) {
                updates += 1;
            }
        }
        assert_eq!(updates, 1);
        // Counters are exact regardless of the throttle.
        let live = hub.list_connections().remove(0);
        assert_eq!((live.rx_bytes, live.tx_bytes), (5000, 10_000));

        // Closing always emits a final update carrying the final counters.
        hub.mark_connection_closed("t1");
        match events.try_recv().expect("final update on close") {
            TelemetryEvent::ConnectionUpdated(c) => {
                assert_eq!(c.status, ConnectionStatus::Closed);
                assert_eq!(c.rx_bytes, 5000);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn pending_connection_updates_are_flushed_by_the_periodic_tick() {
        let hub = udp_test_hub(500, 30_000, 20);
        let mut events = hub.subscribe();
        hub.record_connection(udp_template("t2"), false);
        while events.try_recv().is_ok() {}
        // A burst right after creation is throttled (interval not elapsed yet).
        hub.update_connection_traffic("t2", 1, 1);
        assert!(events.try_recv().is_err());
        tokio::time::sleep(Duration::from_millis(40)).await;
        hub.tick_bandwidth_sample();
        let mut saw_update = false;
        while let Ok(ev) = events.try_recv() {
            if let TelemetryEvent::ConnectionUpdated(c) = ev {
                assert_eq!((c.rx_bytes, c.tx_bytes), (1, 1));
                saw_update = true;
            }
        }
        assert!(saw_update, "tick must flush the pending counter update");
    }
}
