## About GmSSL

[![Build Status](https://travis-ci.org/zhajio1988/GmSSL.svg?branch=master)](https://travis-ci.org/zhajio1988/GmSSL)

GmSSL is an open source cryptographic toolkit that provide first level support of Chinese national cryptographic algorithms and protocols which specified in the GM/T serial standards. As a branch of the OpenSSL project, GmSSL provides API level compatibility with OpenSSL and maintains all the functionalities. Existing projects such as Apache web server can be easily ported to GmSSL with minor modification and simple rebuild. Since the first release in late 2014, GmSSL has been selected as one of the six recommended cryptographic projects by Open Source China and the winner of the 2015 Chinese Linux Software Award.

## Features

 - Support [Chinese GM/T cryptographic standards](http://gmssl.org/docs/standards.html).
 - Support [hardware cryptographic modules from Chinese vendors](http://www.sca.gov.cn/sca/zxfw/cpxx.shtml).
 - With commercial friendly open source [license](http://gmssl.org/docs/licenses.html).
 - Maintained by the [crypto research group of Peking University](http://infosec.pku.edu.cn).

## GM/T Algorithms

GmSSL will support all the following GM/T cryptographic algorithms:

 - SM3 (GM/T 0004-2012): cryptographic hash function with 256-bit digest length.
 - SM4 (GM/T 0002-2012): block cipher with 128-bit key length and 128-bit block size, also named SMS4.
 - SM2 (GM/T 0003-2012): elliptic curve cryptographic schemes including digital signature scheme, public key encryption, (authenticated) key exchange protocol and one recommended 256-bit prime field curve `sm2p256v1`.
 - SM9 (GM/T 0044-2016): pairing-based cryptographic schemes including identity-based digital signature, encryption, (authenticated) key exchange protocol and one 256-bit recommended BN curve.
 - ZUC (GM/T 0001-2012): stream cipher, with 128-EEA3 encryption algorithm and 128-EIA3 integrity algorithm.
 - SM1 and SSF33: block ciphers with 128-bit key length and 128-bit block size without public specification, only provided with chip.
 
GmSSL supports many useful cryptographic algorithms and schemes:

 - Public-key schemes: Paillier, ECIES (Elliptic Curve Integrated Encryption Scheme)
 - Pairing-based cryptography: BF-IBE, BB1-IBE
 - Block ciphers and modes: Serpent, Speck
 - Block cipher modes: FPE (Format-Preserver Encryption)
 - OTP (One-Time Password) based on SM3/SM4 (GM/T 0021-2012)
 - Encoding: Base58

OpenSSL algorithms such as ECDSA, RSA, AES, SHA-1 are all remained in GmSSL.

## GM/T Protocols

The GM/T standards cover 2 protocls:

 - SSL VPN Protocol  (GM/T 0024-2014)
 - IPSec VPN Protocol (GM/T 0022-2014)
 
The GM/T 0024-2014 SSL VPN protocol is different from IETF TLS from the follows aspects:

 - Current version of TLS is 1.2 (0x0303) while GM/T SSL version is 1.1 (0x0101)
 - The handshake protocol of GM/T SSL is diffenet from TLS handshake.
 - There is an optional different record protocol in GM/T SSL designed for VPN applications.
 - GM/T SSL has 12 ciphersuites, some of these ciphers do not provide forward secrecy.
 
GM/T 0024-2014 Ciphersuites: 

```
 1. GMTLS_SM2DHE_SM2SIGN_WITH_SM1_SM3  {0xe0,0x01}
 2. GMTLS_SM2ENC_WITH_SM1_SM3          {0xe0,0x03}
 3. GMTLS_SM9DHE_SM9SIGN_WITH_SM1_SM3  {0xe0,0x05}
 4. GMTLS_SM9ENC_WITH_SM1_SM3          {0xe0,0x07}
 5. GMTLS_RSA_WITH_SM1_SM3             {0xe0,0x09}
 6. GMTLS_RSA_WITH_SM1_SHA1            {0xe0,0x0a}
 7. GMTLS_SM2DHE_SM2SIGN_WITH_SMS4_SM3 {0xe0,0x11}
 8. GMTLS_SM2ENC_WITH_SMS4_SM3         {0xe0,0x13}
 9. GMTLS_SM9DHE_SM9SIGN_WITH_SMS4_SM3 {0xe0,0x15}
10. GMTLS_SM9ENC_WITH_SMS4_SM3         {0xe0,0x17}
11. GMTLS_RSA_WITH_SMS4_SM3            {0xe0,0x19}
12. GMTLS_RSA_WITH_SMS4_SM3            {0xe0,0x1a}
```

GmSSL supports the standard TLS 1.2 protocol with SM2/SM3/SM4 ciphersuites and the GM/T SSL VPN protocol and ciphersuites.

## APIs

Except for the native C interface and the `gmssl` command line, GmSSL also provide the following interfaces:

 - Java: crypto, X.509 and SSL API through JNI (Java Native Interface).
 - Go: crypto, X.509 and SSL API through CGO.
 - SKF C API: GM/T 0016-2012 Smart token cryptography application interface specification.
 - SDF C API: GM/T 0018-2012 Interface specifications of cryptography device application.
 - SAF C API: GM/T 0019-2012 Universal cryptography service interface specification.
 - SOF C/Java API: GM/T 0020-2012 Certificate application integrated service interface specification.

## Supported Cryptographic Hardwares

 - USB-Key through the SKF ENGINE and the SKF API.
 - PCI-E card through the SDF ENGINE and the SDF API.
 - GM Instruction sets (SM3/SM4) through the GMI ENGINE.

## Quick Start

This short guide describes the build, install and typical usage of the `gmssl` command line tool. Visit http://gmssl.org for more documents.

Download ([GmSSL-master.zip](https://github.com/zhajio1988/GmSSL/archive/master.zip)), uncompress it and go to the source code folder. On Linux and OS X, run the following commands:

 ```sh
 $ ./config
 $ make
 $ sudo make install
 ```
 
After installation you can run `gmssl version -a` to print detailed information.

The `gmssl` command line tool supports SM2 key generation through `ecparam` or `genpkey` option, support SM2 signing and encryption through `pkeyutl` option, support SM3 through `sm3` or `dgst` option, support SM4 through `sms4` or `enc` option.

The following are some examples.

SM3 digest generation:

```
$ echo -n "abc" | gmssl sm3
(stdin)= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

SM4 encryptiona and decryption:

```sh
$ gmssl sms4 -in README.md -out README.sms4
$ gmssl sms4 -d -in README.sms4
```

SM2 private key generation:

```sh
$ gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out skey.pem
```

Derive the public key from the generated SM2 private key:

```sh
$ gmssl pkey -pubout -in skey.pem -out vkey.pem
```

SM2 signature generation and verification:

```sh
$ gmssl pkeyutl -sign -pkeyopt ec_scheme:sm2 -inkey skey.pem -in README.md -out README.md.sig
$ gmssl pkeyutl -verify -pkeyopt ec_scheme:sm2 -pubin -inkey vkey.pem -in README.md -sigfile README.md.sig
```

Generate SM2 encryption key pair and do SM2 public key encyption/decryption. It should be noted `pkeyutl -encrypt` should only be used to encrypt short messages such as session key and passphrase.

```sh
$ gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve -out dkey.pem
$ gmssl pkey -pubout -in dkey.pem -out ekey.pem
$ echo "Top Secret" | gmssl pkeyutl -encrypt -pkeyopt ec_scheme:sm2 -pubin -inkey ekey.pem -out ciphertext.sm2
$ gmssl pkeyutl -decrypt -pkeyopt ec_scheme:sm2 -inkey dkey.pem -in ciphertext.sm2
```

Self-signed SM2 certificate generation:

```sh
$ gmssl req -new -x509 -key skey.pem -out cert.pem
```
Add SHA-512/224 SHA-512/256 digest algm

SHA-512/224 digest generation:

```
$ echo -n "abc" | gmssl sha512t224
(stdin)= 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa 
$ echo -n "abc" | gmssl dgst -sha512t224
(stdin)= 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa 
```
SHA-512/256 digest generation:

```
$ echo -n "abc" | gmssl sha512t256
(stdin)= 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa 
$ echo -n "abc" | gmssl dgst -sha512t256
(stdin)= 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa 
```
can also generate signature use below command:

```
$ gmssl genrsa -out privatekey.pem 2048
$ echo -n "abc" | gmssl dgst -sha512t224 -sign privatekey.pem -hex
(stdin)= 34936983a9b9b50baa34e49fd846a90e556081e41b4386912bc796d1b092dbb1f8cc03cafe1fce9a0d1eef85597aefb8b16cea33042c0c531eb9a2d852185ae521ae900448a1447cd902919d4ac612511701ea074b7ca98c51d977b7afc6b91565683e58ae92c790096c3a2d2041c0e4bd11674ce2af7126eb0b705bd2c434bca7672bfacdb5a729156ac1ff81e773d5ccf046007a72a72b9b03c79ef4a675967560890f2c60a31a592dbbc70a39f8e47d960f1f01fc2e1f9e54704bb1d6cffa59449a954aa892eb43fe67bd914bfd70ca24eaabff66e6c8c3dba4e2496ebbeb4d01e25293027b757f62c0ec23ce376cfd33e9505f6d83beddf27aa301f89b21 
```
