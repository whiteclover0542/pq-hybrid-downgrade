// Minimal crypto/tls client with the library's default key-exchange configuration (v1.6 client survey).
// Certificate verification is disabled because it only talks to the local loopback test server.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
)

func main() {
	addr := flag.String("connect", "127.0.0.1:8545", "server address")
	flag.Parse()
	conn, err := tls.Dial("tcp", *addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("negotiated=%v\n", conn.ConnectionState().CurveID)
}
