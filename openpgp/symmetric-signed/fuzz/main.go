package symmetricsigned

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	pgperrors "golang.org/x/crypto/openpgp/errors"
)

var keyringHex = `99020d0451f92e3c011000d283f9c79cb116d4151aa5cb284cf7653bf1f1de5e5a5b2f726dd31de53cd603a3fa80f58a4fff79043438c3c3c02d7f610ad89b38fc83703eebb55ff4d7841d2111dfe41763e5c817925880f0d8b18e3a42965178cf25b6ecf791dc523e65ca3fb49d31ecef16155479d5596aebca55436f892110fdebf5c5723c1dc9a6f5667566284b2ad9854fcea8e54da77aec246bcfa4012d2821540d7bb711950fd36fb487d94b77047437ea12f43ced45b78ecf7bbb4a8c1f47166b6d0ed7c2664f371fffc4f42b3f9c5efb23d72de2bcebbb11f8bbffd4a2591fe6d5a8020f98419f97dbf6d7c4d7994c135bbe29615e04247187c403a5c18b5ca7d5f58457480328e757ceda5b2cd3e3ab300cc9dbf7caf2aba05e7d2beedeb067df565d772b6d31705639eeaeb32c30ee127b5154b95a14a61320d637ff437dc565dfbee5e9401690c97e39b6f1030854402b6b0bf549b0052aa743528f5fa17109c6ddcd12d636f2ef07e7ae527adf6b7d2c5f2cf2a894e8907ef81e7bc14d214792da7c3eaf995005b35b9735c72cdcec1458ff79db9d970e9c6114f0ed5203a6fd405ca880319c48cea286f706f78c424cd04d4e3803284a198c2115eb9109dd54aebc84ae32ae08d27efc8094c3064b51eb44142feb56e8394ca6f1c95898f73487a29549107c2a1fd8b6b45300973df537ccc21e237c1b07a5906b8a76fdfa3965ca40712f0011010001b43c427269616e204769746f6e6761204d617265746520284f70656e5047502054657374204b657929203c62676d617265746540676d61696c2e636f6d3e890238041301020022050251f92e3c021b03060b090807030206150802090a0b0416020301021e01021780000a091070ada826d5b89c4c44180fff626475ead536d63e0a703001ce67e7793c586e6874fc278bf482f32513b5573debb903d287d01d121e2bed338169cf9073667c1e31a6e1a147ba23db1be32d282c0bb586505a069d577f50c297a1eaa7e00c0c5d913aa624c76972e16ff6f6688c98ed74ef15977c3afca9812319b986e4dc16c28b6aff9d6b66f40d904d66a8c352bb4116f5683581f1d8112081014da9a0a9f99502f091c659eca33c0f772baa99d17832c1c86cc22fbab6d6e0e8cb1a2165623bb177baa6bb1c0d8c55be1a239d18ce55a3bfedb6250547bb1c498dd6969f4e1c3bbcc6f7cafbbb1314c961b70e16172692011e29421640637fe51f03457ff8680c21164f0414bea3e88a52dd8e1aac1781ae5144c9da693aa8afaee7255a080110e90ca7d2e3051fc0720b189cb1edb00e000c1c4dbb8c6a4d8b1d40383c7a92e8fc8b93d610f1f95630e665a0ff7aafd7209ee5f9f76829c2b906a36cb05f3f2754547921102a463d93671bc2ec0c1e049f8b3260d76219b8c27261a7e4e7b183344f66bb7cdfde6b096507d453b839939bb29e9d6f900371635f9b69b9781ec7e58bd547732758990a8c365c2089ea11116a849ae9d835f83ec1b577aa9c5dd685efbe05c757533c52aae7b17816674897a7435b5237395b4c53c049d88f96c43877f9c9cfc3f091cb8bd9df594fce9193b2b42090d0830a5ec323e0d8316c104ba7065b48eed1f43d66b9020d0451f92e3c011000fb5e11794823e1c6423217ecb65d4bfd2ae608b0b5bfa232f8b0bbef387db51c754f9083a480104f1baef40cf1914633444aca809fccd3595e713e5b9b49bf92a26f47911209d29fed4ba1969a58410d480c1cc4d9abb8344e8bce62ae73dc4cf752bad0fc7d0e408b665f060bf946278e03d7e536060cb14990c9ca40a61ddbb076d9de3d233e7712aead53a5fde931c4c2a11d287f4a40aff5b4910fd7475b89cf9db8181e79d0a04b7d3d5adb7eacb346a113aa245566c0ab186a3bc63218f3492d6b94c3a33fe75e69f0400a225ccdd9d722617badf305693a0a71df72b5e3c670137743e36a02c3c9c868b58cef4a5aaad25891fc36bdf5b854e789bf1f834ed9e43a1e286fefc60e4da4e61739da3b86ec34cbd263d83491f92b84fa267eee8085332e6c8836a0d62f901d7c6545b57a31c149d1d89f37883cc7aed4d14e6fe9dff443c5115f3a6faf31c76010c3e484ca26a04572d75d711f73e5454d51c25174ed7bc0fc9a69f69306b46d3ff7fe36c328dd01833db17714479a6c8d45e09710b3f13274de96ceff6670fd93a28f77bc505455162e3af1d1bc065f39817730643b16335bf7568dc7f6d5ae9580a231a409bc131128f9be45dfecec247852b7ab3a57a09e74794ccc033ee8c74f3506f181b7c2af333542fb62373fe1cfb54cd51506a8074eaacd4b52665765014e47c644c8751de8f3b180c5b9268f001101000189021f041801020009050251f92e3c021b0c000a091070ada826d5b89c4cc7620fff7673cda41209280911a95467e280d7d87724914777eb793a65befc7952091228a60a6b4842d33aa066b2d0281a7c76565e8c49bfecf27179ea9411d1673ec784b8da5d3c15b7533648134c828faf91bf35d6484ba8587b6e4075f32609731f3eaff7a8664103b3e3d4f7b6d0a78916341f3c9e3334db81f91f8d31ec5464c2ea587e29c4f39e70b8dae193d1433b1caaec582388541b2241cce3e76a1641c2e89f4a360c462dac198bda5a9901857fbaee5e28f324d2b1d6186dfe47a6c631e1df0f0bc13e8f9746ba96212c21544fbdcd203a6bb72470534cea6bc590af3c5169149eb6d01c508dd28ff47c65925273a76cd6026da90c0bf242e93c60291b18d60c18fe2705503f7418fb51e4f3cdf336be3689c11c4d014bcc68cd56a0f26ef55ed3e8cfa96e2729d662688afabbfc9594569fe88324bd355bde758917721680f6b5d171e31520441658586f038e00a5990ed3c5d7cf9d7cb7fa79cf2dfb165d484ef6de90f13f4e6ee46bb3df915ff5790a8e2f88696bd87342440a816513a7e9bdba550e9852653ba3dabdedb1c7dbcec5e558c55bc3e8c30152268519d3500706f64918476b213e4592b8845124590a59a59b8a234eab56347ea33cc9272af1aee829f62ef9aae0d8abbff127e6e179186e395795afb0bb22f8269aa32c4fe702140b39fc93e07bcfe8870dd01349193db7149e27dd8e8ecc73d770cbc0`

type keyring struct {
	el openpgp.EntityList
}

func newKeyring() (*keyring, error) {
	data, err := hex.DecodeString(keyringHex)
	if err != nil {
		return nil, err
	}

	r := bytes.NewBuffer(data)

	el, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	return &keyring{el: el}, nil
}

func (kr *keyring) KeysById(id uint64) []openpgp.Key {
	return kr.el.KeysById(id)
}

func (kr *keyring) DecryptionKeys() []openpgp.Key {
	return kr.el.DecryptionKeys()
}

func (kr *keyring) KeysByIdUsage(id uint64, requiredUsage byte) []openpgp.Key {
	return kr.el.KeysByIdUsage(id, requiredUsage)
}

// Random passphrase for my "OpenPGP Test Key". It is also the same passphrase
// used for symmetric encryption.
const passphrase = "NieMo2liuvoh2iighee3oo"

var plainBytes = []byte("One ring to rule them all. One ring to find them, one ring to bring them all and in the darkness to bind them")

func newPromptFunction() func([]openpgp.Key, bool) ([]byte, error) {
	first := true

	// We use a closure to keep track of how many times we have
	// been called. Otherwise, on malformed messages, we could be
	// called in an infinite loop.
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric || len(keys) != 0 {
			// We never call openpgp.ReadMessage() with
			// any private keys. So we do not expect them
			// here, and we always expect to be asked for
			// a symmetric passphrase.
			panic(fmt.Sprintf("Prompt function called with unexpected arguments: %+v, %v", keys, symmetric))
		}

		if first {
			first = false
			return []byte(passphrase), nil
		}

		return nil, errors.New("Already called (probably malformed msg)")

	}
}

func Fuzz(data []byte) int {
	kr, err := newKeyring()
	if err != nil {
		panic(err)
	}

	md, err := openpgp.ReadMessage(bytes.NewBuffer(data), kr,
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
			// check. We return 1 for it.
			return 1
		}
		// It failed to parse correctly and not due to an
		// integrity problem. The structure is wrong, so we return 0.
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

	return 1
}
