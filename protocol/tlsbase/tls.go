package tlsbase

type TLS struct {
	Host     string
	Port     int
	SNI      string
	Insecure bool
}
