package symmetricunsigned

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp"
	pgperrors "golang.org/x/crypto/openpgp/errors"
)

// An empty Keyring
type emptyKR struct {
}

func (kr emptyKR) KeysById(id uint64) []openpgp.Key {
	return nil
}

func (kr emptyKR) DecryptionKeys() []openpgp.Key {
	return nil
}

func (kr emptyKR) KeysByIdUsage(uint64, byte) []openpgp.Key {
	return nil
}

const passphrase = "insecure"

var plainBytes = []byte("One ring to rule them all. One ring to find them, one ring to bring them all and in the darkness to bind them")

func newPromptFunction() func([]openpgp.Key, bool) ([]byte, error) {
	first := true

	// We use a closure to keep track of how many times we have
	// been called. Otherwise, on malformed messages, we could be
	// called in an infinite loop.
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			// We only support passhphrases for symmetrically
			// encrypted decryption keys
			return nil, errors.New("Decrypting private keys not supported")
		}

		if first {
			first = false
			return []byte(passphrase), nil
		}

		return nil, errors.New("Already called")

	}
}

func Fuzz(data []byte) int {
	md, err := openpgp.ReadMessage(bytes.NewBuffer(data), emptyKR{},
		newPromptFunction(), nil)
	if err != nil {
		return 0
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, md.UnverifiedBody)
	if err != nil {
		if _, ok := err.(pgperrors.SignatureError); ok {
			// The message structure is correct. It parsed
			// correctly, but only failed an integrity
			// check. We return 1 for it. Fully correct
			// messages will return 2 below.
			return 1
		}

		return 0
	}

	verifiedBody := buf.Bytes()
	if !bytes.Equal(plainBytes, verifiedBody) {
		// There seems to be no way of telling if an MDC was
		// checked for. If there was, we could check for that
		// and panic here. For now, we just assume that this
		// is a non-MDC protected message that has been
		// modified.
		return 1

	}

	return 2
}
