package notify

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// tinySMTP is a minimal SMTP server that captures one message, enough to
// smoke-test smtpMailer's plaintext/STARTTLS-less path against a real socket.
func tinySMTP(t *testing.T) (addr string, received chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		bw := bufio.NewWriter(conn)
		write := func(s string) { _, _ = bw.WriteString(s + "\r\n"); _ = bw.Flush() }

		write("220 tiny ESMTP")
		var body strings.Builder
		inData := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case inData:
				if line == "." {
					inData = false
					write("250 OK queued")
					select {
					case received <- body.String():
					default:
					}
					continue
				}
				body.WriteString(line + "\n")
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				write("250 tiny")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				write("250 OK")
			case strings.HasPrefix(line, "DATA"):
				write("354 send data")
				inData = true
			case strings.HasPrefix(line, "QUIT"):
				write("221 bye")
				return
			default:
				write("250 OK")
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), received
}

func TestSMTPMailerSendsMessage(t *testing.T) {
	addr, received := tinySMTP(t)
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	_, _ = fscan(portStr, &port)

	m := NewSMTPMailer(SMTPConfig{
		Host: host, Port: port, From: "hsmdoctor@example.com",
		To: []string{"ops@example.com"}, TLS: TLSNone,
	})
	if err := m.Send("Test subject", "Hello body line", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "Subject: Test subject") {
			t.Errorf("subject not delivered: %q", msg)
		}
		if !strings.Contains(msg, "Hello body line") {
			t.Errorf("body not delivered: %q", msg)
		}
		if !strings.Contains(msg, "To: ops@example.com") {
			t.Errorf("recipient header missing: %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no message received")
	}
}

// fscan is a tiny helper to parse the port without importing strconv here.
func fscan(s string, out *int) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	*out = n
	return 1, nil
}
