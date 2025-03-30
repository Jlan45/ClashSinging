package hysteria2

import (
	"github.com/quic-go/quic-go"
	"net"
	"time"
)

type Hysteria2Conn struct {
	QuicStream   quic.Stream
	Hysteria2Obj *Hysteria2
}

func (h Hysteria2Conn) Read(b []byte) (n int, err error) {
	return h.QuicStream.Read(b)
}

func (h Hysteria2Conn) Write(b []byte) (n int, err error) {
	return h.QuicStream.Write(b)

}

func (h Hysteria2Conn) Close() error {
	return h.QuicStream.Close()
}

func (h Hysteria2Conn) LocalAddr() net.Addr {
	return h.Hysteria2Obj.QuicConn.LocalAddr()
}

func (h Hysteria2Conn) RemoteAddr() net.Addr {
	return h.Hysteria2Obj.QuicConn.RemoteAddr()

}

func (h Hysteria2Conn) SetDeadline(t time.Time) error {
	return h.QuicStream.SetDeadline(t)
}

func (h Hysteria2Conn) SetReadDeadline(t time.Time) error {
	return h.QuicStream.SetReadDeadline(t)
}

func (h Hysteria2Conn) SetWriteDeadline(t time.Time) error {
	return h.QuicStream.SetWriteDeadline(t)
}
