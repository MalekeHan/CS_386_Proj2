// Usage example:
// 		go run generator.go 999 013456 7890AB
//
// This will generate 999 hex-encoded plaintext/ciphertext pairs in the form of:
//		<hex encoded plaintext> <hex encoded ciphertext>

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %v <num> <k1> <k2>\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		usage()
	}
	n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse n: %v\n", err)
		os.Exit(1)
	}

	k1bytes, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse k1 has hex: %v\n", err)
		os.Exit(1)
	}
	k2bytes, err := hex.DecodeString(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse k2 has hex: %v\n", err)
		os.Exit(1)
	}

	if len(k1bytes) != 3 {
		fmt.Fprintf(os.Stderr, "k1 must be 24 bits (3 bytes)\n")
		os.Exit(1)
	}
	if len(k2bytes) != 3 {
		fmt.Fprintf(os.Stderr, "k2 must be 24 bits (3 bytes)\n")
		os.Exit(1)
	}

	var k1, k2 uint32
	k1 = uint32(binary.BigEndian.Uint16(k1bytes))
	k1 = (k1 << 8) | uint32(k1bytes[2])
	k2 = uint32(binary.BigEndian.Uint16(k2bytes))
	k2 = (k2 << 8) | uint32(k2bytes[2])

	for i := 0; i < n; i++ {
		genPair(k1, k2)
	}
}

func genPair(k1, k2 uint32) {
	var m, c [8]byte
	binary.BigEndian.PutUint32(m[:], rand.Uint32())
	binary.BigEndian.PutUint32(m[4:], rand.Uint32())
	c = doubleEncrypt(k1, k2, m)
	fmt.Printf("%v %v\n", hex.EncodeToString(m[:]), hex.EncodeToString(c[:]))
}

func doubleEncrypt(k1, k2 uint32, m [8]byte) (c [8]byte) {
	return encrypt(k2, encrypt(k1, m))
}

func doubleDecrypt(k1, k2 uint32, c [8]byte) (m [8]byte) {
	return decrypt(k1, decrypt(k2, c))
}

const rounds = 64

func encrypt(k uint32, m [8]byte) (c [8]byte) {
	// Only keep the least significant 24 bits
	k &= (1 << 24) - 1

	v0, v1 := binary.BigEndian.Uint32(m[:]), binary.BigEndian.Uint32(m[4:])
	const delta = 0x9E3779B9
	sum := uint32(0)
	key := [4]uint32{k, k, k, k}
	for i := 0; i < rounds; i++ {
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum&3])
		sum += delta
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3])
	}
	binary.BigEndian.PutUint32(c[:], v0)
	binary.BigEndian.PutUint32(c[4:], v1)
	return
}

func decrypt(k uint32, c [8]byte) (m [8]byte) {
	// Only keep the least significant 24 bits
	k &= (1 << 24) - 1

	v0, v1 := binary.BigEndian.Uint32(c[:]), binary.BigEndian.Uint32(c[4:])
	const delta = 0x9E3779B9
	sum := uint32((delta * rounds) & math.MaxUint32)
	key := [4]uint32{k, k, k, k}
	for i := 0; i < rounds; i++ {
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11)&3])
		sum -= delta
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum&3])
	}
	binary.BigEndian.PutUint32(m[:], v0)
	binary.BigEndian.PutUint32(m[4:], v1)
	return
}
