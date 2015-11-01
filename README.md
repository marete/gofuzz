This repository contains programs, scripts and both initial and generated corpora that I use with [Dimitry Vyukov's Gofuzz](https://github.com/dvyukov/go-fuzz) to fuzz various Go libraries.

At the current time, the programs, scripts and corpora included are only those that I have used to fuzz [golang.org/x/crypto/openpgp](golang.org/x/crypto/openpgp), and they reflect my ongoing efforts in that area.

## Trophies
* [x/crypto/openpgp: ReadMessage(): Panic on invalid input in packet.nextSubpacket](https://github.com/golang/go/issues/11503) **fixed**
* [x/crypto/openpgp: ReadMessage(): Panic on invalid input in packet.PublicKeyV3.setFingerPrintAndKeyId](https://github.com/golang/go/issues/11504) **fixed**
* [x/crypto/openpgp: ReadMessage(): Panic on invalid input in math/big.nat.div](https://github.com/golang/go/issues/11505) **fixed**
