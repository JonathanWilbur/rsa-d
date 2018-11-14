/*
    FIPS 186-4 only supports RSA moduli of bit-lengths 1024, 2048, and 3072.
    -- Source: Section 5.1

    An approved hash function, as specified in FIPS 180, shall be used during
    the generation of key pairs and digital signatures. When used during the
    generation of an RSA key pair (as specified in this Standard), the length
    in bits of the hash function output block shall meet or exceed the security
    strength associated with the bit length of the modulus n (see SP 800-57).
*/
module rsa.primes;
import csprng.system;
import std.bigint : BigInt;
import rsa.utilities : bytesToHex;

///
public alias millerRabinTest = millerRabinProbabilisticPrimalityTest;
/// See FIPS 186-4, Section C.3.1
public
bool millerRabinProbabilisticPrimalityTest (in BigInt value, in uint iterations)
{
    if (!(value & 1u)) return false; // If it is divisible by 2, it is obviously composite.
    CSPRNG rng = new CSPRNG();

    step1:
        size_t a = (value.uintLength * 32u);
        while ((value - 1) % (BigInt(2u) ^^ a)) a--;

    step2:
        BigInt m = ((value - 1) / (BigInt(2u) ^^ a));

    step3:
        // lengthInBits

    step4:
        for (uint i = 0u; i < iterations; i++)
        {
            import csprng.system;

            step4_1:
                BigInt b = BigInt("0x" ~ bytesToHex(cast(ubyte[]) rng.getBytes(128u)));

            step4_2:
                if (b <= 1 || b == (value - 1)) goto step4_1;

            step4_3:
                BigInt z = modpow(b, m, value);

            step4_4:
                if (z == 1 || z == (value - 1)) goto step4_7;

            step4_5:
                for (uint j = 1u; j < (a - 1); j++)
                {
                    step4_5_1:
                        z = ((z * z) % value);

                    step4_5_2:
                        if (z == (value - 1)) goto step4_7;

                    step4_5_3:
                        if (z == 1) goto step4_6;
                }

            step4_6:
                return false;

            step4_7:
                continue;
        }

    Step5:
        return true;
}




public @system pure
BigInt modpow (in BigInt b, BigInt exponent, in BigInt modulus)
{
    if (modulus == BigInt(0))
        throw new Exception("Modulus was zero!");
    BigInt r = BigInt(1);
    BigInt base = (b % modulus);
    while (exponent > BigInt(0))
    {
        if (base == BigInt(0)) return BigInt(0);
        if (exponent % BigInt(2)) r = ((r * base) % modulus);
        exponent /= BigInt(2);
        base = ((base * base) % modulus);
    }
    return r;
}

@system
unittest
{
    assert(modpow(BigInt(65), BigInt(17), BigInt(3233)) == BigInt(2790));
    assert(modpow(BigInt(2790), BigInt(413), BigInt(3233)) == BigInt(65));
}