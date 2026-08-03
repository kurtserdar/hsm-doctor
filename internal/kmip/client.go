// Package kmip is a small, read-only KMIP client for diagnostics: it connects
// to a KMIP server over (mutual) TLS, discovers protocol versions, locates the
// managed objects and reads their attributes, then evaluates a security
// posture. It speaks KMIP 1.x over TTLV using the gemalto/kmip-go primitives.
//
// It is deliberately read-only — it never creates, modifies or destroys keys.
package kmip

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
)

// Config describes how to reach a KMIP server.
type Config struct {
	Endpoint   string // host:port
	ServerCA   string // PEM file used to verify the server certificate
	ClientCert string // client certificate for mutual TLS
	ClientKey  string // client private key for mutual TLS
	Insecure   bool   // skip server certificate verification (labs only)
	Timeout    time.Duration
}

// Client is a connected KMIP client.
type Client struct {
	conn    net.Conn
	timeout time.Duration
	major   int
	minor   int
	counter uint64
}

// Dial connects to the KMIP server described by cfg.
func Dial(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("kmip: endpoint is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.Insecure {
		tlsCfg.InsecureSkipVerify = true
	} else if cfg.ServerCA != "" {
		pem, err := os.ReadFile(cfg.ServerCA)
		if err != nil {
			return nil, fmt.Errorf("reading server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("server CA %q contains no certificates", cfg.ServerCA)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		if cfg.ClientCert == "" || cfg.ClientKey == "" {
			return nil, fmt.Errorf("kmip: both client-cert and client-key are required for mutual TLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", cfg.Endpoint, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", cfg.Endpoint, err)
	}
	return newClient(conn, timeout), nil
}

// newClient wraps an established connection. Kept separate from Dial so the
// protocol logic can be tested over any net.Conn. KMIP 1.4 is the highest 1.x
// version we speak; DiscoverVersions narrows it down.
func newClient(conn net.Conn, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{conn: conn, timeout: timeout, major: 1, minor: 4}
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// ProtocolVersion returns the negotiated protocol version as "major.minor".
func (c *Client) ProtocolVersion() string { return fmt.Sprintf("%d.%d", c.major, c.minor) }

// nextBatchID returns a fresh 16-byte batch item id.
func (c *Client) nextBatchID() []byte {
	n := atomic.AddUint64(&c.counter, 1)
	id := make([]byte, 16)
	binary.BigEndian.PutUint64(id[8:], n)
	return id
}

// roundTrip sends a single-operation request and returns the response payload
// TTLV, or an error if the batch item did not succeed.
func (c *Client) roundTrip(op kmip14.Operation, payload interface{}) (ttlv.TTLV, error) {
	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: c.major,
				ProtocolVersionMinor: c.minor,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{{
			UniqueBatchItemID: c.nextBatchID(),
			Operation:         op,
			RequestPayload:    payload,
		}},
	}
	req, err := ttlv.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encoding %s request: %w", op, err)
	}
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(req); err != nil {
		return nil, fmt.Errorf("sending %s: %w", op, err)
	}
	resp, err := readTTLV(c.conn)
	if err != nil {
		return nil, fmt.Errorf("reading %s response: %w", op, err)
	}
	return responsePayload(resp, op)
}

// readTTLV reads exactly one length-prefixed TTLV value from r. A TTLV header
// is 3 bytes of tag, 1 byte of type, and a 4-byte big-endian length.
func readTTLV(r io.Reader) (ttlv.TTLV, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[4:8])
	buf := make([]byte, 8+int(n))
	copy(buf, header)
	if _, err := io.ReadFull(r, buf[8:]); err != nil {
		return nil, err
	}
	return ttlv.TTLV(buf), nil
}

// responsePayload navigates a ResponseMessage to the first batch item, checks
// its result status, and returns its ResponsePayload TTLV.
func responsePayload(resp ttlv.TTLV, op kmip14.Operation) (ttlv.TTLV, error) {
	for t := resp.ValueStructure(); len(t) > 0; t = t.Next() {
		if t.Tag() != kmip14.TagBatchItem {
			continue
		}
		var status kmip14.ResultStatus
		var sawStatus bool
		var message string
		var payload ttlv.TTLV
		for b := t.ValueStructure(); len(b) > 0; b = b.Next() {
			switch b.Tag() {
			case kmip14.TagResultStatus:
				status = kmip14.ResultStatus(b.ValueEnumeration())
				sawStatus = true
			case kmip14.TagResultMessage:
				message = b.ValueTextString()
			case kmip14.TagResponsePayload:
				payload = b
			}
		}
		if !sawStatus || status != kmip14.ResultStatusSuccess {
			if message == "" {
				message = status.String()
			}
			return nil, fmt.Errorf("KMIP %s failed: %s", op, message)
		}
		return payload, nil
	}
	return nil, fmt.Errorf("KMIP %s response had no batch item", op)
}
