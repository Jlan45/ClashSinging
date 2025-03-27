package utils

import (
	"github.com/Jlan45/ClashSinging/protocol/trojan"
	"github.com/Jlan45/ClashSinging/proxy"
	"net"
	"net/url"
	"strconv"
)

func ParseProxyUrl(proxyUrl string) proxy.Proxy {
	parsedURL, err := url.Parse(proxyUrl)
	if err != nil {
		return nil
	}
	switch parsedURL.Scheme {
	case "socks5":
		return nil
	case "trojan":
		return ParseTrojan(parsedURL)
	}
	return nil
}
func ParseTrojan(URLObj *url.URL) proxy.Proxy {
	host, port, err := net.SplitHostPort(URLObj.Host)
	if err != nil {
		host = URLObj.Host
		port = "443"
	}
	portInt, err := strconv.Atoi(port)
	pass, hasPass := URLObj.User.Password()
	if !hasPass {
		return nil
	}
	return trojan.Trojan{
		Host:     host,
		Port:     portInt,
		Password: pass,
	}
}
