// Run from Xray-core 0f3d884786f9ec73d3be8899cb6b9e1e6dd3c41e:
// GOMAXPROCS=1 go run -p 1 /absolute/path/to/generate.go /absolute/path/to/vectors.json
// All keys are test-only. ML-KEM encapsulation is randomized on regeneration.
package main

import (
	"bytes"
	"crypto/mlkem"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/xtls/xray-core/proxy/vless/encryption"
	"lukechampine.com/blake3"
)

type vector map[string]any

type memory struct {
	net.Conn
	bytes.Buffer
}

func (m *memory) Write(b []byte) (int, error) { return m.Buffer.Write(b) }
func (m *memory) Read(b []byte) (int, error)  { return m.Buffer.Read(b) }

func pattern(n int, factor int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * factor)
	}
	return b
}

func h(b []byte) string { return hex.EncodeToString(b) }

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--verify-rust" {
		verifyRust(os.Args[2])
		return
	}
	result := vector{"xray_revision": "0f3d884786f9ec73d3be8899cb6b9e1e6dd3c41e", "blake3_go": "v1.4.1"}
	material := pattern(96, 1)
	var kdfs []vector
	for _, length := range []int{0, 16, 32, 96, 1024, 1216, 4096} {
		context := pattern(length, 137)
		key := make([]byte, 32)
		blake3.DeriveKey(key, string(context), material)
		kdfs = append(kdfs, vector{"context": h(context), "material": h(material), "key": h(key)})
	}
	result["kdf"] = kdfs
	var seeds []vector
	for _, seed := range [][]byte{make([]byte, 64), bytes.Repeat([]byte{1}, 64), pattern(64, 1)} {
		private, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			panic(err)
		}
		secret, ciphertext := private.EncapsulationKey().Encapsulate()
		seeds = append(seeds, vector{"seed": h(seed), "public": h(private.EncapsulationKey().Bytes()), "ciphertext": h(ciphertext), "secret": h(secret)})
	}
	result["seeds"] = seeds
	var aeads []vector
	for _, aes := range []bool{true, false} {
		for _, field := range []struct {
			name              string
			length, keyLength int
		}{
			{"nfs", 16, 32}, {"fresh_up", 1216, 96}, {"fresh_down", 1120, 96},
			{"resumed_up", 32, 96}, {"resumed_down", 16, 96}, {"rekey", 53, 96},
		} {
			context := pattern(field.length, 137)
			key := material[:field.keyLength]
			a := encryption.NewAEAD(context, key, aes)
			plaintext := pattern(32, 13)
			header := make([]byte, 5)
			encryption.EncodeHeader(header, len(plaintext)+16)
			one := a.Seal(nil, nil, plaintext, header)
			max := a.Seal(nil, encryption.MaxNonce, plaintext, nil)
			two := a.Seal(nil, nil, plaintext, header)
			aeads = append(aeads, vector{"field": field.name, "aes": aes, "context": h(context), "material": h(key), "plaintext": h(plaintext), "header": h(header), "one": h(one), "max": h(max), "two": h(two)})
		}
	}
	result["aead"] = aeads
	var rekeys []vector
	for _, aes := range []bool{true, false} {
		context, plain := pattern(16, 3), pattern(32, 13)
		wire := &memory{}
		conn := encryption.NewCommonConn(wire, aes)
		conn.UnitedKey = material
		conn.AEAD = encryption.NewAEAD(context, material, aes)
		copy(conn.AEAD.Nonce[:], encryption.MaxNonce)
		for range 3 {
			if _, err := conn.Write(plain); err != nil {
				panic(err)
			}
		}
		rekeys = append(rekeys, vector{"aes": aes, "context": h(context), "material": h(material), "plaintext": h(plain), "wire": h(wire.Bytes())})
	}
	result["rekey"] = rekeys
	var ctrs []vector
	for _, iv := range [][]byte{make([]byte, 16), bytes.Repeat([]byte{255}, 16), append(make([]byte, 8), bytes.Repeat([]byte{255}, 8)...), append(make([]byte, 12), bytes.Repeat([]byte{255}, 4)...)} {
		plain := pattern(1088, 7)
		cipher := bytes.Clone(plain)
		encryption.NewCTR(material, iv).XORKeyStream(cipher, cipher)
		ctrs = append(ctrs, vector{"material": h(material), "iv": h(iv), "plaintext": h(plain), "ciphertext": h(cipher)})
	}
	result["ctr"] = ctrs
	var masks []vector
	for _, header := range [][]byte{{0x15, 3, 3, 0, 2}, {0x17, 3, 3, 255, 255}, {0x17, 3, 3, 0, 5}} {
		iv := pattern(16, 1)
		plain := append(bytes.Clone(header), pattern(60, 13)...)
		conn := &memory{}
		xor := encryption.NewXorConn(conn, encryption.NewCTR(material, iv), nil, 0, 0)
		for _, b := range plain {
			if _, err := xor.Write([]byte{b}); err != nil {
				panic(err)
			}
		}
		masks = append(masks, vector{"material": h(material), "iv": h(iv), "plaintext": h(plain), "ciphertext": h(conn.Bytes())})
	}
	result["mask"] = masks
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(output, '\n'), 0644); err != nil {
		panic(err)
	}
}

func verifyRust(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var vectors []map[string]string
	if err := json.Unmarshal(data, &vectors); err != nil {
		panic(err)
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}
	for _, vector := range vectors {
		key, err := mlkem.NewDecapsulationKey768(decode(vector["seed"]))
		if err != nil {
			panic(err)
		}
		secret, err := key.Decapsulate(decode(vector["ciphertext"]))
		if err != nil || !bytes.Equal(secret, decode(vector["secret"])) {
			panic("Rust to Go decapsulation mismatch")
		}
		if !bytes.Equal(key.EncapsulationKey().Bytes(), decode(vector["public"])) {
			panic("Rust to Go public key mismatch")
		}
	}
	fmt.Printf("Verified %d Rust/AWS-LC encapsulations with Go crypto/mlkem\n", len(vectors))
}
