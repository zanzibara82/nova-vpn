CREATE TABLE telemetry_receipts (
    id uuid PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    processed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX telemetry_receipts_server_time ON telemetry_receipts (server_id, processed_at);
CREATE INDEX connection_events_handshake ON connection_events (server_id, device_id)
    WHERE event = 'handshake_observed';
