package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

func dialTaskProxy(ctx context.Context, raw, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if raw == "" {
		return dialer.DialContext(ctx, "tcp", address)
	}
	u, e := url.Parse(raw)
	if e != nil {
		return nil, e
	}
	if u.Scheme == "socks5" {
		d, e := proxy.FromURL(u, dialer)
		if e != nil {
			return nil, e
		}
		contextDialer, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("SOCKS5 proxy does not support request cancellation")
		}
		return contextDialer.DialContext(ctx, "tcp", address)
	}
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	var conn net.Conn
	if u.Scheme == "https" {
		conn, e = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", host)
	} else {
		conn, e = dialer.DialContext(ctx, "tcp", host)
	}
	if e != nil {
		return nil, e
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: http.Header{}}
	if u.User != nil {
		request.SetBasicAuth(u.User.Username(), func() string { v, _ := u.User.Password(); return v }())
		request.Header.Set("Proxy-Authorization", request.Header.Get("Authorization"))
		request.Header.Del("Authorization")
	}
	if e = request.Write(conn); e != nil {
		conn.Close()
		return nil, e
	}
	reader := bufio.NewReader(conn)
	response, e := http.ReadResponse(reader, request)
	if e != nil {
		conn.Close()
		return nil, e
	}
	if response.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT status %d", response.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	if reader.Buffered() > 0 {
		return &bufferedProxyConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

// SyscallConn forwards to the underlying connection so the egress relay can
// pass this socket over SCM_RIGHTS; a CONNECT reply that arrived together with
// the first tunneled bytes produces this wrapper.
func (c *bufferedProxyConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("underlying proxy connection %T has no syscall handle", c.Conn)
	}
	return sc.SyscallConn()
}

func (c *bufferedProxyConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// BufferedBytes drains bytes that were read past the CONNECT response. The
// egress relay only receives the raw fd, so they have to be replayed separately.
func (c *bufferedProxyConn) BufferedBytes() []byte {
	buffered := c.reader.Buffered()
	if buffered == 0 {
		return nil
	}
	out := make([]byte, buffered)
	if _, err := io.ReadFull(c.reader, out); err != nil {
		return nil
	}
	return out
}
