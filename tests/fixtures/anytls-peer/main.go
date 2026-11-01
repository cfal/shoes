package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	anytls "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type handler struct{}

func (handler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if destination.Fqdn == uot.MagicAddress {
		if err := relayUDP(conn); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	if err := N.ReportHandshakeSuccess(conn); err != nil {
		return
	}
	io.Copy(conn, conn)
}

func relayUDP(conn net.Conn) error {
	request, err := uot.ReadRequest(conn)
	if err != nil {
		return err
	}
	if !request.IsConnect || !request.Destination.Addr.IsLoopback() {
		return fmt.Errorf("fixture requires connected UoT to a loopback address")
	}
	remote, err := net.DialUDP("udp", nil, request.Destination.UDPAddr())
	if err != nil {
		return err
	}
	defer remote.Close()
	if err := N.ReportHandshakeSuccess(conn); err != nil {
		return err
	}
	packets := uot.NewConn(conn, *request)
	buffer := make([]byte, 65535)
	for {
		n, err := packets.Read(buffer)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := remote.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if _, err := remote.Write(buffer[:n]); err != nil {
			return err
		}
		n, err = remote.Read(buffer)
		if err != nil {
			return err
		}
		if _, err := packets.Write(buffer[:n]); err != nil {
			return err
		}
	}
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
