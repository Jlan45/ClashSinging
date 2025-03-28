package utils

import (
	"github.com/Jlan45/ClashSinging/protocol/socks5"
	"github.com/Jlan45/ClashSinging/protocol/tlsbase"
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
	portInt, err := strconv.Atoi(parsedURL.Port())
	pass, _ := parsedURL.User.Password()
	switch parsedURL.Scheme {
	case "socks5":
		return socks5.Socks5{
			Host:     parsedURL.Host,
			Port:     portInt,
			Username: parsedURL.User.Username(),
			Password: pass,
		}
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
		TLSConfig: tlsbase.TLS{
			Insecure: func() bool {
				if URLObj.Query().Get("allowInsecure") == "true" || URLObj.Query().Get("allowInsecure") == "1" {
					return true
				}
				return false
			}(),
			SNI: URLObj.Query().Get("sni"),
		},
	}
}
