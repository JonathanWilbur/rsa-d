# Design Decisions

## Why can't I choose the RSA encryption exponent, `e`?

This library does not support any choice for `e` other than 65537, because
65537 is both balanced between performance and security and required by
DKIM. Prohibiting changing this reduces the odds of somebody doing something
stupid and makes this library more secure by reducing complexity.

## Why don't you support Multi-prime RSA?

This library will _never_ support multi-prime RSA, because, according to
[this](https://crypto.stackexchange.com/questions/15823/multiple-prime-rsa-how-many-primes-can-i-use-for-a-2048-bit-modulus#15859),
Multi-prime RSA is prohibited by both FIPS 140-2 and FIPS 186-4, as well
as various other security specifications.