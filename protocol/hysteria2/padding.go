package hysteria2

import "github.com/Jlan45/ClashSinging/tools"

var (
	authRequestPadding  = tools.Padding{Min: 256, Max: 2048}
	authResponsePadding = tools.Padding{Min: 256, Max: 2048}
	tcpRequestPadding   = tools.Padding{Min: 64, Max: 512}
	tcpResponsePadding  = tools.Padding{Min: 128, Max: 1024}
)
