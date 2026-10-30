//go:build ignore

// Run from Xray 0afec66085a85191e9dd2a4a6646c7c9a94688d1 (v26.10.29):
// GOMAXPROCS=1 go run -p 1 /path/to/shoes/tests/fixtures/sudoku/xray.go
// -verify FILE cross-decodes the Rust export instead of generating samples.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
)

type config struct {
	Password string   `json:"password"`
	ASCII    string   `json:"ascii"`
	Tables   []string `json:"custom_tables,omitempty"`
	Min      uint32   `json:"padding_min"`
	Max      uint32   `json:"padding_max"`
}

type sample struct {
	Config config `json:"config"`
	Packed bool   `json:"packed"`
	Plain  []byte `json:"plain"`
	Wire   []byte `json:"wire"`
}

type memory struct {
	net.Conn
	input  *bytes.Reader
	output bytes.Buffer
}

func (m *memory) Read(p []byte) (int, error)  { return m.input.Read(p) }
func (m *memory) Write(p []byte) (int, error) { return m.output.Write(p) }

func wrap(s sample, m *memory) net.Conn {
	c := &sudoku.Config{Password: s.Config.Password, Ascii: s.Config.ASCII,
		CustomTables: s.Config.Tables, PaddingMin: s.Config.Min, PaddingMax: s.Config.Max}
	var conn net.Conn
	var err error
	if s.Packed {
		conn, err = sudoku.NewPackedTCPConn(m, c)
	} else {
		conn, err = sudoku.NewTCPConn(m, c)
	}
	if err != nil {
		panic(err)
	}
	return conn
}

func main() {
	verify := flag.String("verify", "", "Rust fixture JSON to cross-decode")
	flag.Parse()
	if *verify != "" {
		file, err := os.Open(*verify)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		var samples []sample
		if err = json.NewDecoder(file).Decode(&samples); err != nil {
			panic(err)
		}
		if len(samples) == 0 {
			panic("empty fixture")
		}
		for i, s := range samples {
			decoded, err := io.ReadAll(wrap(s, &memory{input: bytes.NewReader(s.Wire)}))
			if err != nil || !bytes.Equal(decoded, s.Plain) {
				panic(fmt.Sprintf("sample %d: decode=%x want=%x error=%v", i, decoded, s.Plain, err))
			}
		}
		fmt.Printf("Xray decoded %d Rust samples\n", len(samples))
		return
	}
	var samples []sample
	for _, c := range []config{
		{Password: "example"},
		{Password: " test password ", ASCII: "ascii", Min: 100, Max: 100},
		{Password: "negative seed", Tables: []string{"xpxvvpvv", "vxpvxvvp"}, Min: 100, Max: 100},
		{Password: "", Tables: []string{"", "xpxvvpvv"}, Min: 5, Max: 15},
	} {
		for _, packed := range []bool{false, true} {
			s := sample{Config: c, Packed: packed}
			raw := &memory{}
			conn := wrap(s, raw)
			for _, size := range []int{1, 2, 3, 13, 14, 256} {
				data := make([]byte, size)
				for i := range data {
					data[i] = byte(i*37 + size)
				}
				if _, err := conn.Write(data); err != nil {
					panic(err)
				}
				s.Plain = append(s.Plain, data...)
			}
			s.Wire = raw.output.Bytes()
			samples = append(samples, s)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(samples); err != nil {
		panic(err)
	}
}
