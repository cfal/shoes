package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type handler struct{}

func (handler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if destination.Fqdn == "sp.v2.udp-over-tcp.arpa" {
		var connect [1]byte
		if _, err := io.ReadFull(conn, connect[:]); err != nil {
			return
		}
		if connect[0] != 1 {
			return
		}
		if _, err := M.SocksaddrSerializer.ReadAddrPort(conn); err != nil {
			return
		}
	}
	if err := N.ReportHandshakeSuccess(conn); err != nil {
		return
	}
	io.Copy(conn, conn)
}

func main() {
	service, err := anytls.NewService("test", anytls.ServiceOptions{
		Handler:       handler{},
		PaddingScheme: []byte("stop=4\n0=31-31\n1=70000-70000\n2=100-100"),
	})
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			if err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}
}
