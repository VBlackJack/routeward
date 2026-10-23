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
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
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

#[derive(Clone)]
pub struct TelemetryHub {
    connections: Arc<DashMap<String, TrackedConnection>>,
    active_cancellers: Arc<DashMap<String, watch::Sender<bool>>>,
    logs: Arc<RwLock<VecDeque<LogEntry>>>,
    bandwidth_history: Arc<RwLock<VecDeque<BandwidthSample>>>,
    event_tx: broadcast::Sender<TelemetryEvent>,
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
        let broadcast_cap = constants
            .event_broadcast_capacity
            .max(MIN_BROADCAST_CAPACITY);
        let (event_tx, _) = broadcast::channel(broadcast_cap);

        Self {
            connections: Arc::new(DashMap::new()),
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
        self.connections.insert(conn.id.clone(), conn.clone());
        let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
    }

    pub fn update_connection_traffic(&self, id: &str, delta_rx: u64, delta_tx: u64) {
        self.add_traffic(delta_rx, delta_tx);
        let updated = if let Some(mut entry) = self.connections.get_mut(id) {
            entry.rx_bytes += delta_rx;
            entry.tx_bytes += delta_tx;
            Some(entry.clone())
        } else {
            None
        };
        if let Some(conn) = updated {
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
        }
    }

    pub fn mark_connection_closed(&self, id: &str) {
        self.active_cancellers.remove(id);
        let updated = if let Some(mut entry) = self.connections.get_mut(id) {
            entry.status = ConnectionStatus::Closed;
            Some(entry.clone())
        } else {
            None
        };
        if let Some(conn) = updated {
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
        }
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

        let updated = if let Some(mut entry) = self.connections.get_mut(id) {
            if entry.status == ConnectionStatus::Active {
                entry.status = ConnectionStatus::Closed;
                Some(entry.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(conn) = updated {
            let _ = self.event_tx.send(TelemetryEvent::ConnectionUpdated(conn));
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
            .filter(|c| c.value().status != ConnectionStatus::Active)
            .map(|c| c.key().clone())
            .collect();
        for id in closed_ids {
            self.connections.remove(&id);
        }
        let _ = self.event_tx.send(TelemetryEvent::ConnectionsCleared);
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

        let snap = self.snapshot();
        let _ = self.event_tx.send(TelemetryEvent::Telemetry(snap));
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
}
