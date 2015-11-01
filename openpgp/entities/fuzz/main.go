package entities

import (
	"bytes"

	"golang.org/x/crypto/openpgp"
)

func Fuzz(data []byte) int {
	r := bytes.NewBuffer(data)

	_, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return 0
	}

	return 1
}
