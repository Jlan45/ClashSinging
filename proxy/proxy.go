package proxy

import (
	"context"
	"net"
)

type Proxy interface {
	Init() error //针对需要初始化的代理，如hysteria2
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
