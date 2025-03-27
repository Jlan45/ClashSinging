package trojan

import (
	"net"
	"time"
)

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
