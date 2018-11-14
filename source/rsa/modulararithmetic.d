module rsa.modulararithmetic;
import std.bigint : BigInt;

/**
    Given, a public exponent, e, and modulus, N, the calculates the private
    exponent, d, where:

    $(MONO (e * d) % Phi(N) == 1)

    This uses the Extended Euclidian Algorithm to find d, which, in mathematical
    terms, is the $(I modular multiplicative inverse) of e with respect to the
    modulus, Phi(N).
*/
public @system // pure nothrow
BigInt modularInverse (BigInt a, BigInt m)
{
    BigInt m0 = m;
    BigInt y = BigInt(0);
    BigInt x = BigInt(1);
    if (m == 1) return BigInt(0);
    while (a > 1)
    {
        if (m == 0) throw new Exception("BigInt division by zero! Are you sure the variable 'a' in modularInverse() is prime?");
        BigInt quotient = (a / m);
        BigInt temp = m;
        m = (a % m);
        a = temp;
        temp = y;
        y = x - (quotient * y);
        x = temp;
    }
    if (x < 0) x += m0;
    return x;
}

@system
unittest
{
    assert(modularInverse(BigInt(3u), BigInt(11u)) == BigInt(4u));
}