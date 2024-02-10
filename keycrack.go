// Usage example:
// 		go run generator.go 999 013456 7890AB | go run keycrack.go
//
// This will generate 999 hex-encoded plaintext/ciphertext pairs in the form of:
//		<hex encoded plaintext> <hex encoded ciphertext>
//
// ...then pipe those pairs to this keycracker, which will then output (if
// it succeeds at breaking the keys):
//		{
//		    "key_1": "013456",
//		    "key_2": "7890ab"
//		}

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// A plaintext and ciphertext pair from stdin.
//
// Each line of the input consists of two hex-encoded eight-byte sequences. The
// first sequence of each line is plaintext, and the second is its corresponding
// ciphertext. (We don't get the intermediate ciphertext from the first round of
// encryption.)
type textpair struct {
	plaintext  [8]byte
	ciphertext [8]byte
}

// The two, 24-bit keys used to encrypt the plaintext into ciphertext (and to
// decrypt the ciphertext into the plaintext). Since Go doesn't have 24-bit
// numbers, we use `uint32` (a 32-bit integer) instead.
type keypair struct {
	// The key used for the first round of encryption.
	key1 uint32
	// The key used for the second round of encryption.
	key2 uint32
}

// Cracks the keys used to encrypt/decrypt the given plaintext and ciphertext
// pairs.
//
// Your job is to implement this function. Feel free to modify, rename, and
// re-imagine it. We have provided already-implemented helper functions you may
// use, and you may define whatever helper functions or import whatever packages
// you need.
func crack(texts []textpair) keypair {
	cPrimeMap := make(map[string]uint32)

	for keyGuess := uint32(0); keyGuess < (1 << 24); keyGuess++ { //use bit-wise here to loop 2^24 times and exhaust the space
		encryptedMid := encrypt(keyGuess, texts[0].plaintext)     //do the inner encyption with whatever key we are in and the plaintext
		cPrimeMap[hex.EncodeToString(encryptedMid[:])] = keyGuess // create a new entry in our map [c_prime |-> key_guess]
	}

	for keyGuess := uint32(0); keyGuess < (1 << 24); keyGuess++ { //use bit-wise here to loop 2^24 times and exhaust the space
		decryptedMid := decrypt(keyGuess, texts[0].ciphertext)      //do decryption with whatever key we are in and the ciphertext in the same row as the plaintext
		decryptedMidHex := hex.EncodeToString(decryptedMid[:])      // we now convert this to a hex value
		if matchedKey, found := cPrimeMap[decryptedMidHex]; found { //checks if the hex of the decrpyted plaintext is a key in the cPrimeMap : E(k_0, m) = C' = D(k_1, c)

			if testDoubleEncryption(matchedKey, keyGuess, texts[0].plaintext, texts[0].ciphertext) { // we use double encyption to verify if this is the actual correct key pair
				return keypair{key1: matchedKey, key2: keyGuess}
			}
		}
	}

	return keypair{key1: 0, key2: 0} // return all 0s if nothing is found
}

// verication function to test if a key pair is actually correct
func testDoubleEncryption(key1, key2 uint32, plaintext, ciphertext [8]byte) bool {
	testCiphertext := doubleEncrypt(key1, key2, plaintext)
	return testCiphertext == ciphertext
}

/*************************** Provided Helper Code *****************************/
// To complete this assignment you should NOT have to modify any code from here
// onwards.

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

/*************************** Other Provided Code ******************************/

func main() {
	// Parse the ciphertext/plaintext pairs from stdin.
	texts := parse(os.Stdin)

	if len(texts) == 0 {
		fmt.Fprintf(os.Stderr, "need at least one plaintext/ciphertext pair\n")
		os.Exit(1)
	}

	answer := crack(texts)

	printAnswer(answer)
}

// Parses bytes from `reader` into a structured representation of the encrypted
// database.
func parse(reader io.Reader) []textpair {
	var pairs []textpair
	s := bufio.NewScanner(reader)
	for s.Scan() {
		parts := strings.Fields(s.Text())
		if len(parts) == 0 {
			// skip empty lines
			continue
		}
		if len(parts) != 2 {
			fmt.Println(os.Stderr, "invalid syntax: expected lines of the form <plaintext> <ciphertext>\n")
			os.Exit(1)
		}
		plainBytes, err := hex.DecodeString(parts[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not parse plaintext as hex: %v\n", err)
			os.Exit(1)
		}
		cipherBytes, err := hex.DecodeString(parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not parse ciphertext as hex: %v\n", err)
			os.Exit(1)
		}

		if len(plainBytes) != 8 {
			fmt.Fprintf(os.Stderr, "plaintext must be 8 bytes\n", err)
			os.Exit(1)
		}
		if len(cipherBytes) != 8 {
			fmt.Fprintf(os.Stderr, "ciphertext must be 8 bytes\n", err)
		}

		var newPair textpair
		copy(newPair.plaintext[:], plainBytes)
		copy(newPair.ciphertext[:], cipherBytes)
		pairs = append(pairs, newPair)
	}
	if err := s.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "could not read stdin: %v\n", err)
		os.Exit(1)
	}
	return pairs
}

func printAnswer(keys keypair) {
	var key1Bytes [4]byte
	var key2Bytes [4]byte

	binary.BigEndian.PutUint32(key1Bytes[:], keys.key1)
	binary.BigEndian.PutUint32(key2Bytes[:], keys.key2)

	type answers struct {
		Key1 string `json:"key_1"`
		Key2 string `json:"key_2"`
	}

	answerString, err := json.MarshalIndent(answers{
		Key1: hex.EncodeToString(key1Bytes[1:]),
		Key2: hex.EncodeToString(key2Bytes[1:]),
	}, "", "    ")

	if err != nil {
		panic(err)
	}

	fmt.Println(string(answerString))
}
