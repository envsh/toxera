package relayhub

import (
	"fmt"
	"math/big"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58DecodeTab [256]int

func init() {
	for i := range base58DecodeTab {
		base58DecodeTab[i] = -1
	}
	for i, c := range base58Alphabet {
		base58DecodeTab[c] = i
	}
}

func base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var chars []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		chars = append(chars, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < len(data) && data[i] == 0; i++ {
		chars = append(chars, base58Alphabet[0])
	}
	for i, j := 0, len(chars)-1; i < j; i, j = i+1, j-1 {
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty base58 string")
	}
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		if int(c) >= len(base58DecodeTab) || base58DecodeTab[c] == -1 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(base58DecodeTab[c])))
	}
	leadingZeros := 0
	for _, c := range s {
		if c == rune(base58Alphabet[0]) {
			leadingZeros++
		} else {
			break
		}
	}
	data := n.Bytes()
	result := make([]byte, leadingZeros+len(data))
	copy(result[leadingZeros:], data)
	return result, nil
}
