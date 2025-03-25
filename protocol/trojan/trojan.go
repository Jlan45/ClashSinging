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
}

func (t Trojan) Dial(network, addr string) (c net.Conn, err error) {
	ctx := context.Background()
	host, port, err := net.SplitHostPort(addr)
	context.WithValue(ctx, "info", map[string]string{
		"addr":    addr,
		"network": network,
		"host":    host,
		"port":    port,
	})
	return t.DialContext(ctx, network, addr)
}

func (t Trojan) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
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
	if ctx.Value("info") == nil {
		host, port, _ := net.SplitHostPort(address)
		ctx = context.WithValue(ctx, "info", map[string]string{
			"addr":    address,
			"network": network,
			"host":    host,
			"port":    port,
		})
	}
	sc := TrojanConn{
		RawConn: rawConn,
		TlsConn: tlsConn,
		Ctx:     ctx,
		Info:    t,
	}
	// 发送trojan握手，Trojan没有握手
	return sc, nil
}

type TrojanConn struct {
	RawConn net.Conn        // 原始连接
	TlsConn net.Conn        // tls连接
	Ctx     context.Context //上下文里面写链接的addr
	Info    Trojan          // 代理信息
}

func (t TrojanConn) Read(b []byte) (n int, err error) {
	n, err = t.TlsConn.Read(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (t TrojanConn) Write(b []byte) (n int, err error) {

	//+-----------------------+---------+----------------+---------+----------+
	//| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
	//+-----------------------+---------+----------------+---------+----------+
	//|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
	//+-----------------------+---------+----------------+---------+----------+
	passHash := tools.SHA224String(t.Info.Password)
	buf := bytes.Buffer{}
	buf.Write([]byte(passHash))
	buf.Write([]byte{0x0d, 0x0a})
	//+-----+------+----------+----------+
	//| CMD | ATYP | DST.ADDR | DST.PORT |
	//+-----+------+----------+----------+
	//|  1  |  1   | Variable |    2     |
	//+-----+------+----------+----------+
	switch t.Ctx.Value("info").(map[string]string)["network"] {
	case "tcp":
		buf.Write([]byte{0x01})
	case "udp":
		buf.Write([]byte{0x03})
	}
	ip := net.ParseIP(t.Ctx.Value("info").(map[string]string)["host"])
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
		buf.Write([]byte{byte(len(t.Ctx.Value("info").(map[string]string)["host"]))})
		buf.Write([]byte(t.Ctx.Value("info").(map[string]string)["host"]))
	}
	port, _ := strconv.Atoi(t.Ctx.Value("info").(map[string]string)["port"])
	buf.Write([]byte{byte(port >> 8), byte(port)})
	buf.Write([]byte{0x0d, 0x0a})
	buf.Write(b)
	n, err = t.TlsConn.Write(buf.Bytes())
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
