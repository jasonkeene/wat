// Proxy is a transparent TCP proxy that you can stick in between two ends of
// a connection. It will read individual lines from both ends, report those
// lines to stdout, and write them to the other end.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	target, addr := getFlags()

	targetConn, err := net.Dial("tcp", target)
	fatalerror("Unable to dial", err)
	list, err := net.Listen("tcp", addr)
	fatalerror("Unable to listen", err)
	sourceConn, err := list.Accept()
	fatalerror("Unable to accept", err)

	go intercept(targetConn, sourceConn)
	intercept(sourceConn, targetConn)
}

func intercept(w io.Writer, r io.Reader) {
	in := bufio.NewReader(r)
	for {
		text, err := in.ReadString('\n')
		fatalerror("Unable to read", err)
		_, err = fmt.Print(text)
		fatalerror("Unable to output", err)
		_, err = fmt.Fprint(w, text)
		fatalerror("Unable to write", err)
	}
}

func getFlags() (string, string) {
	var (
		target string
		addr   string
	)
	flag.StringVar(&target, "target", "127.0.0.1:8181", "address to connect to")
	flag.StringVar(&addr, "addr", "127.0.0.1:8182", "address to bind to")
	flag.Parse()
	return target, addr
}

func fatalerror(msg string, err error) {
	if err != nil {
		log.Fatalf(msg+": %s", err)
	}
}
