package proxy

import (
	"context"
	"net"
)

type Proxy interface {
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
