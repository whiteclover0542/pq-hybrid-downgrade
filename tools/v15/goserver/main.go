// Minimal crypto/tls server for the v1.5 negotiation-function comparison.
// It completes TLS 1.3 handshakes with the configured groups and logs the negotiated group.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8545", "listen address")
	pem := flag.String("pem", "", "PEM file holding the certificate and private key")
	groups := flag.String("groups", "X25519MLKEM768,X25519", "comma-separated CurvePreferences")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*pem, *pem)
	if err != nil {
		log.Fatal(err)
	}
	ids := map[string]tls.CurveID{"X25519MLKEM768": tls.X25519MLKEM768, "X25519": tls.X25519}
	var prefs []tls.CurveID
	for _, name := range strings.Split(*groups, ",") {
		id, ok := ids[name]
		if !ok {
			log.Fatalf("unknown group %s", name)
		}
		prefs = append(prefs, id)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CurvePreferences: prefs}
	listener, err := tls.Listen("tcp", *addr, config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening %s groups=%s", *addr, *groups)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("handshake error: %v", err)
				return
			}
			log.Printf("negotiated=%v", tlsConn.ConnectionState().CurveID)
		}(conn)
	}
}
