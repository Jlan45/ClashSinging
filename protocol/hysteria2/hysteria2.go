package hysteria2

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"github.com/Jlan45/ClashSinging/protocol/tlsbase"
	"github.com/Jlan45/ClashSinging/tools"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"net"
	"net/http"
	"strconv"
	"sync"
)

type Hysteria2 struct {
	Host      string
	Port      int
	Password  string
	TLSConfig tlsbase.TLS
	QuicConn  quic.EarlyConnection
	QuicMutex sync.Mutex
}

func (h *Hysteria2) Init() error {
	var conn quic.EarlyConnection
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         h.TLSConfig.SNI,
			InsecureSkipVerify: h.TLSConfig.Insecure,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(h.Host, strconv.Itoa(h.Port)))
			if err != nil {
				return nil, err
			}
			pktConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			qc, err := quic.DialEarly(ctx, pktConn, addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	httpClient := http.Client{
		Transport: tr,
	}
	// 发起 HTTP/3 请求
	req, err := http.NewRequest("POST", "https://"+h.Host+":"+strconv.Itoa(h.Port)+"/auth", nil)
	req.Proto = "HTTP/3"
	req.Host = "hysteria"
	// 设置请求头
	req.Header.Set("Hysteria-Auth", h.Password)
	req.Header.Set("Hysteria-CC-RX", strconv.Itoa(0))
	req.Header.Set("Hysteria-Padding", tools.GenerateRandomString(20))
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 233 {
		return errors.New("auth failed")
	}
	h.QuicConn = conn
	return nil
}
func (h *Hysteria2) Dial(network, addr string) (net.Conn, error) {
	ctx := context.Background()
	return h.DialContext(ctx, network, addr)
}

func (h *Hysteria2) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	h.QuicMutex.Lock()
	defer h.QuicMutex.Unlock()
	stream, err := h.QuicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	//生成TCP请求header
	handshakeBuffer := make([]byte, 0)
	handshakeBuffer = quicvarint.Append(handshakeBuffer, 0x401)
	handshakeBuffer = quicvarint.Append(handshakeBuffer, uint64(len(address)))
	handshakeBuffer = append(handshakeBuffer, []byte(address)...)
	paddingStr := authRequestPadding.String()
	handshakeBuffer = quicvarint.Append(handshakeBuffer, uint64(len(paddingStr)))
	handshakeBuffer = append(handshakeBuffer, []byte(paddingStr)...)
	//发起TCP请求
	_, err = stream.Write(handshakeBuffer)
	if err != nil {
		return nil, err
	}
	respBuffer := bufio.NewReader(stream)
	statuByte, _ := respBuffer.ReadByte()
	switch statuByte {
	case 0x00:
		// 0x00表示成功
	case 0x01:
		//0x01 error
		// 读取错误消息长度
		msgLen, _ := quicvarint.Read(respBuffer)
		msg := make([]byte, msgLen)
		_, err = respBuffer.Read(msg)
		return nil, errors.New(string(msg))
	}
	if err != nil {
		return nil, err
	}
	conn := Hysteria2Conn{
		QuicStream:   stream,
		Hysteria2Obj: h,
	}
	return conn, nil
}
