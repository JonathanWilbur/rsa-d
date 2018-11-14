module rsa.utilities;
import std.bigint : BigInt, divMod;
import std.traits : isIntegral;

/**
    This is needed for converting bytes to BigInt, because BigInt's
    constructor only accepts strings.
*/
public
string bytesToHex(T)(in T[] bytes)
if (is(T == ubyte) || is(T == byte) || is(T == void))
{
    import std.conv : to;
    string ret;
    foreach (b; bytes)
    {
        string hexbyte = b.to!string(16);
        if (hexbyte.length == 1u) hexbyte = ("0" ~ hexbyte);
        ret ~= hexbyte;
    }
    return ret;
}

@system
unittest
{
    assert("00FF12AB" == bytesToHex(cast(ubyte[]) [ 0x00u, 0xFFu, 0x12u, 0xABu ]));
}

/* NOTE:
    https://security.stackexchange.com/questions/90169/rsa-public-key-and-private-key-lengths
    "Traditionally, the "length" of a RSA key is the length, in bits, of the
    modulus. When a RSA key is said to have length "2048", it really means
    that the modulus value lies between 22047 and 22048. Since the public and
    private key of a given pair share the same modulus, they also have, by
    definition, the same "length"."
*/
public @system
BigInt phi (BigInt p, BigInt q)
{
    return ((p-1)*(q-1));
}

@system
unittest
{
    assert(phi(BigInt(79), BigInt(113)) == BigInt(8736));
}

public alias gcd = greatestCommonDenominator;
public @system // can be pure
BigInt greatestCommonDenominator(in BigInt a, in BigInt b)
{
    BigInt dividend = a;
    BigInt divisor = b;

    BigInt quotient;
    BigInt remainder = BigInt(1); // Any arbitrary non-zero will work.
    immutable BigInt bigZero = BigInt(0);
    while (remainder != bigZero)
    {
        divMod(dividend, divisor, quotient, remainder);
        dividend = divisor;
        divisor = remainder;
    }
    return dividend;
}

@system
unittest
{
    assert(greatestCommonDenominator(BigInt(210), BigInt(45)) == BigInt(15));
}

/*
    EVERYTHING BELOW THIS SECTION SHOULD BE DONE AWAY WITH ONCE bigint.toBytes
    IS IMPLEMENTED.
*/

// Implemented because peekUint is not public in std.bigint.BigInt.
uint peekUint (T)(in BigInt b, in T index)
if (isIntegral!T)
{
    BigInt c = (b >> (index * (uint.sizeof << 3)));
    c &= uint.max;
    return cast(uint) c;
}

ubyte[] bigintToBytes (in BigInt b)
in
{
    assert(b.uintLength > 0u);
}
out (ret)
{
    assert(ret.length > 0u);
}
body
{
    ubyte[] ret;
    ret.length = (b.uintLength << 2); // Multiply by 4
    size_t j = 0u;
    while (j < b.uintLength)
    {
        *cast(uint*) &(ret[(j << 2)]) = b.peekUint(j);
        j++;
    }

    version (BigEndian)
    {
        size_t startOfNonPadding = 0u;
        if (b >= 0)
        {
            for (size_t i = 0u; i < (ret.length - 1); i++)
            {
                if (ret[i] != 0x00u) break;
                if (!(ret[i+1] & 0x80u)) startOfNonPadding++;
            }
            ret = ret[startOfNonPadding .. $];
            if (ret[$-1] & 0x80u) ret = (0x00u ~ ret);
        }
        else
        {
            for (size_t i = 0u; i < (ret.length - 1); i++)
            {
                if (ret[i] != 0xFFu) break;
                if (ret[i+1] & 0x80u) startOfNonPadding++;
            }
            ret = ret[startOfNonPadding .. $];
            if (!(ret[$-1] & 0x80u)) ret = (0xFFu ~ ret);
        }
    }
    else version (LittleEndian)
    {
        size_t startOfNonPadding = ret.length;
        if (b >= 0)
        {
            for (size_t i = (ret.length - 1); i > 0u; i--)
            {
                if (ret[i] != 0x00u) break;
                if (!(ret[i-1] & 0x80u)) startOfNonPadding--;
            }
            ret.length = startOfNonPadding;
            if (ret[$-1] & 0x80u) ret ~= 0x00u;
        }
        else
        {
            for (size_t i = (ret.length - 1); i > 0u; i--)
            {
                if (ret[i] != 0xFFu) break;
                if (ret[i-1] & 0x80u) startOfNonPadding--;
            }
            ret.length = startOfNonPadding;
            if (!(ret[$-1] & 0x80u)) ret ~= 0xFFu;
        }
        return ret;
    }
    else static assert(0, "Undetermined endianness! Cannot compile!");
}

@system
unittest
{
    version (LittleEndian)
    {
        assert(toBytes(BigInt(byte.max)) == [ 0x7Fu ]);
        assert(toBytes(BigInt(byte.min)) == [ 0x80u ]);
        assert(toBytes(BigInt(ubyte.max)) == [ 0xFFu, 0x00u ]);
        assert(toBytes(BigInt(ubyte.min)) == [ 0x00u ]);
        assert(toBytes(BigInt(short.max)) == [ 0xFFu, 0x7Fu ]);
        assert(toBytes(BigInt(short.min)) == [ 0x00u, 0x80u ]);
        assert(toBytes(BigInt(ushort.max)) == [ 0xFFu, 0xFFu, 0x00u ]);
        assert(toBytes(BigInt(ushort.min)) == [ 0x00u ]);
        assert(toBytes(BigInt(int.max)) == [ 0xFFu, 0xFFu, 0xFFu, 0x7Fu ]);
        assert(toBytes(BigInt(int.min)) == [ 0x00u, 0x00u, 0x00u, 0x80u ]);
        assert(toBytes(BigInt(uint.max)) == [ 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u ]);
        assert(toBytes(BigInt(uint.min)) == [ 0x00u ]);
        assert(toBytes(BigInt(long.max)) == [ 0xFFu, 0xFFu,0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x7Fu ]);
        assert(toBytes(BigInt(long.min)) == [ 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x80u ]);
        assert(toBytes(BigInt(ulong.max)) == [ 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u ]);
        assert(toBytes(BigInt(ulong.min)) == [ 0x00u ]);
        assert(toBytes(BigInt(1)) == [ 0x01u ]);
        assert(toBytes(BigInt(-1)) == [ 0xFFu ]);
        assert(toBytes(BigInt(3)) == [ 0x03u ]);
        assert(toBytes(BigInt(-3)) == [ 0xFDu ]);
        assert(toBytes(BigInt("18446744073709551619")) == [ // ulong.max + 4
            0x03u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u,
            0x01u
        ]);
        assert(toBytes(BigInt("-2147483651")) == [ // -(int.max + 4)
            0xFDu, 0xFFu, 0xFFu, 0x7Fu,
            0xFFu
        ]);
    }
}