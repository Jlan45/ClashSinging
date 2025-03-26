package vless

type Vless struct {
	Host     string
	Port     int
	Password string
	SNI      string
	Insecure bool
}
