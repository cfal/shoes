//go:build ignore

// Generate with Go 1.27.3: GOMAXPROCS=1 go run -p 1 go_rng.go
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/rand"
	"os"
)

type vector struct {
	Seed  int64    `json:"seed"`
	Words []uint32 `json:"words"`
	Order []int    `json:"order"`
}

func main() {
	seeds := []int64{0, 1, -1, math.MinInt64, math.MaxInt64, 2147483647}
	for _, password := range []string{"", "example", "not-for-logs", " test password "} {
		hash := sha256.Sum256([]byte(password))
		seeds = append(seeds, int64(binary.BigEndian.Uint64(hash[:8])))
	}
	var vectors []vector
	for _, seed := range seeds {
		rng := rand.New(rand.NewSource(seed))
		v := vector{Seed: seed, Words: make([]uint32, 16), Order: make([]int, 288)}
		for i := range v.Words {
			v.Words[i] = rng.Uint32()
		}
		rng = rand.New(rand.NewSource(seed))
		for i := range v.Order {
			v.Order[i] = i
		}
		rng.Shuffle(len(v.Order), func(i, j int) { v.Order[i], v.Order[j] = v.Order[j], v.Order[i] })
		vectors = append(vectors, v)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vectors); err != nil {
		panic(err)
	}
}
