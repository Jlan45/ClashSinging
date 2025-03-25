package trojan

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/Jlan45/ClashSinging/tools"
	"net"
	"strconv"
	"time"
)

type Trojan struct {
	Host     string
	Port     int
	Password string
	SNI      string
	Insecure bool
}

func (t Trojan) Dial(network, addr string) (c net.Conn, err error) {
	ctx := context.Background()
	return t.DialContext(ctx, network, addr)
}

func (t Trojan) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	config := &tls.Config{
		InsecureSkipVerify: t.Insecure,
		ServerName:         t.SNI,
	}
	if t.SNI == "" {
		config.ServerName = t.Host
	}
	rawConn, err := net.Dial("tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, config)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	//+-----------------------+---------+----------------+---------+----------+
	//| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
	//+-----------------------+---------+----------------+---------+----------+
	//|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
	//+-----------------------+---------+----------------+---------+----------+
	passHash := tools.SHA224String(t.Password)
	buf := bytes.Buffer{}
	buf.Write([]byte(passHash))
	buf.Write([]byte{0x0d, 0x0a})
	//+-----+------+----------+----------+
	//| CMD | ATYP | DST.ADDR | DST.PORT |
	//+-----+------+----------+----------+
	//|  1  |  1   | Variable |    2     |
	//+-----+------+----------+----------+
	switch network {
	case "tcp":
		buf.Write([]byte{0x01})
	case "udp":
		buf.Write([]byte{0x03})
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			buf.Write([]byte{0x01})
			buf.Write(ip.To4())
		} else {
			buf.Write([]byte{0x04})
			buf.Write(ip.To16())
		}
	} else {
		buf.Write([]byte{0x03})
		buf.Write([]byte{byte(len(host))})
		buf.Write([]byte(host))
	}
	portInt, _ := strconv.Atoi(port)
	buf.Write([]byte{byte(portInt >> 8), byte(portInt)})
	buf.Write([]byte{0x0d, 0x0a})
	sc := TrojanConn{
		RawConn: rawConn,
		TlsConn: tlsConn,
		Info:    t,
	}
	_, err = tlsConn.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}
	// 发送trojan握手，Trojan没有握手
	return sc, nil
}

type TrojanConn struct {
	RawConn net.Conn // 原始连接
	TlsConn net.Conn // tls连接
	Info    Trojan   // 代理信息
}

func (t TrojanConn) Read(b []byte) (n int, err error) {
	n, err = t.TlsConn.Read(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (t TrojanConn) Write(b []byte) (n int, err error) {

	n, err = t.TlsConn.Write(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (t TrojanConn) Close() error {
	return t.TlsConn.Close()
}

func (t TrojanConn) LocalAddr() net.Addr {
	return t.RawConn.LocalAddr()
}

func (t TrojanConn) RemoteAddr() net.Addr {
	return t.RawConn.RemoteAddr()
}

func (tc TrojanConn) SetDeadline(t time.Time) error {
	return tc.TlsConn.SetDeadline(t)
}

func (tc TrojanConn) SetReadDeadline(t time.Time) error {
	return tc.TlsConn.SetReadDeadline(t)
}

func (tc TrojanConn) SetWriteDeadline(t time.Time) error {

	return tc.TlsConn.SetWriteDeadline(t)
}
