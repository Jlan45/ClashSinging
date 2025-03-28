package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

type Socks5 struct {
	Host     string
	Port     int
	Username string
	Password string
}

func (s Socks5) Init() error {
	return nil
}

type Socks5Conn struct {
	RawConn net.Conn // 原始连接
	Info    Socks5   // 代理信息
}

func (s Socks5Conn) handshake() error {
	// 发送socks5版本号
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	_, err := s.RawConn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	if err != nil {
		return err
	}
	// 接收socks5握手响应
	buf := make([]byte, 256)
	n, err := s.RawConn.Read(buf)
	if n != 2 {
		return errors.New("invalid socks5 handshake response")
	}
	if err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return errors.New("invalid socks5 version")
	}
	var authType byte
	authType = buf[1]
	switch authType {
	case 0x00:
		// 不需要认证
		return nil
	case 0x02:
		// 需要认证
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		byteUsername := []byte(s.Info.Username)
		bytePassword := []byte(s.Info.Password)
		var authBuf bytes.Buffer
		authBuf.WriteByte(0x01)
		authBuf.WriteByte(byte(len(byteUsername)))
		authBuf.Write(byteUsername)
		authBuf.WriteByte(byte(len(bytePassword)))
		authBuf.Write(bytePassword)
		_, err = s.RawConn.Write(authBuf.Bytes())
		if err != nil {
			return err
		}
		// 接收socks5认证响应
		buf = make([]byte, 256)
		n, err = s.RawConn.Read(buf)
		if n != 2 {
			return errors.New("invalid socks5 auth response")
		}
		if err != nil {
			return err
		}
		if buf[1] != 0x00 {
			return errors.New("socks5 auth failed")
		}
	}
	return nil
}

func (s Socks5Conn) Read(b []byte) (n int, err error) {
	//TODO implement me
	length, err := s.RawConn.Read(b)
	if err != nil {
		return 0, err
	}
	return length, nil
}

func (s Socks5Conn) Write(b []byte) (n int, err error) {
	length, err := s.RawConn.Write(b)
	if err != nil {
		return 0, err
	}
	return length, nil
}

func (s Socks5Conn) Close() error {
	s.RawConn.Close()
	return nil
}

func (s Socks5Conn) LocalAddr() net.Addr {
	return s.RawConn.LocalAddr()
}

func (s Socks5Conn) RemoteAddr() net.Addr {
	return s.RawConn.RemoteAddr()
}

func (s Socks5Conn) SetDeadline(t time.Time) error {
	return s.RawConn.SetDeadline(t)
}

func (s Socks5Conn) SetReadDeadline(t time.Time) error {
	return s.RawConn.SetReadDeadline(t)
}

func (s Socks5Conn) SetWriteDeadline(t time.Time) error {
	return s.RawConn.SetWriteDeadline(t)
}

func (s Socks5) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return nil, err
	}
	sc := Socks5Conn{
		RawConn: conn,
		Info:    s,
	}
	// 发送socks5握手
	err = sc.handshake()
	if err != nil {
		return nil, err
	}
	// 发送socks5链接请求
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	var atyp byte
	if ip != nil {
		if ip.To4() != nil {
			atyp = 0x01 // IPv4
		} else {
			atyp = 0x04 // IPv6
		}
	} else {
		atyp = 0x03 // 域名
	}
	conn.Write([]byte{0x05, 0x01, 0x00, atyp})
	switch atyp {
	case 0x01: // IPv4
		conn.Write(ip.To4())
	case 0x04: // IPv6
		conn.Write(ip.To16())
	case 0x03: // 域名
		conn.Write([]byte{byte(len(host))})
		conn.Write([]byte(host))
	}
	portNum, _ := strconv.Atoi(port)
	conn.Write(binary.BigEndian.AppendUint16([]byte{}, uint16(portNum)))

	// 接收socks5链接响应
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	if buf[1] != 0x00 {
		return nil, errors.New("socks5 connect failed")
	}
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s Socks5) Dial(network, addr string) (c net.Conn, err error) {
	ctx := context.Background()
	return s.DialContext(ctx, network, addr)
}
