package hysteria2

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/Jlan45/ClashSinging/protocol/tlsbase"
	"github.com/Jlan45/ClashSinging/tools"
	"github.com/quic-go/quic-go/http3"
	"net"
	"net/http"
	"strconv"
)

type Hysteria2 struct {
	Host      string
	Port      int
	Password  string
	TLSConfig tlsbase.TLS
	QuicConn  net.Conn
}

func (h Hysteria2) Init() error {
	httpClient := http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: h.TLSConfig.Insecure,
				ServerName:         h.TLSConfig.SNI,
			},
		},
	}
	//if h3Transport, ok := httpClient.Transport.(*http3.Transport); ok {
	//	sess, err := h3Transport.GetSession(req.URL)
	//}
	// 发起 HTTP/3 请求
	req, err := http.NewRequest("POST", "https://138.2.31.176:32467/auth", nil)
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
	return nil
}
func (h Hysteria2) Dial(network, addr string) (net.Conn, error) {
	ctx := context.Background()
	return h.DialContext(ctx, network, addr)
}

func (h Hysteria2) DialContext(ctx context.Context, network, address string) (net.Conn, error) {

}
