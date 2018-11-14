import asn1.constants;
import asn1.codecs.der;
import csprng.system;
import rsa.modulararithmetic;
import rsa.primes;
import rsa.utilities;
import std.bigint;
import std.stdio : File, writeln;
import std.traits : isIntegral, isUnsigned;

// TODO: Multi-prime encoding
// TODO: fromBytes
// TODO: toString

///
public alias RSAPrivateKeyVersion = RivestShamirAdlemanPrivateKeyVersion;
/// INTEGER { two-prime(0), multi(1) }
public
enum RivestShamirAdlemanPrivateKeyVersion : ubyte
{
    twoPrime = 0u,
    multiPrime = 1u
}

// NOTE: DKIM requires exponents of 65537, per https://www.ietf.org/rfc/rfc4871.txt.
///
public alias RSAPrivateKey = RivestShamirAdlemanPrivateKey;
/**
    From $(LINK https://tools.ietf.org/html/rfc3447, RFC3447):

    $(PRE
        RSAPrivateKey ::= SEQUENCE {
            version           Version,
            modulus           INTEGER,  -- n
            publicExponent    INTEGER,  -- e
            privateExponent   INTEGER,  -- d
            prime1            INTEGER,  -- p
            prime2            INTEGER,  -- q
            exponent1         INTEGER,  -- d mod (p-1)
            exponent2         INTEGER,  -- d mod (q-1)
            coefficient       INTEGER,  -- (inverse of q) mod p
            otherPrimeInfos   OtherPrimeInfos OPTIONAL }

        OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
    )
*/
public
class RivestShamirAdlemanPrivateKey
{
    public RSAPrivateKeyVersion vers;
    public BigInt modulus;
    public uint publicExponent;
    public BigInt privateExponent;
    public BigInt prime1;
    public BigInt prime2;
    public BigInt exponent1;
    public BigInt exponent2;
    public BigInt coefficient;
    public RSAPrivateKeyOtherPrimeInfo[] otherPrimeInfos;

    ///
    private alias generate2048BitRSAProbablePrimes = generateRSAProbablePrimesImpl!(2048u);
    ///
    private alias generate3072BitRSAProbablePrimes = generateRSAProbablePrimesImpl!(3072u);
    ///
    private alias generateRSAProbablePrimesImpl = generateRivestShamirAdlemanProbablePrimesImpl;
    /**
        I have chosen to make this a template so you cannot create an RSA key
        pair of non FIPS-compliant length.

        This generates a prime number using the method of Random Primes, outlined
        in FIPS 186-4, Appendix B.3.3.
    */
    private @system
    BigInt[2] generateRivestShamirAdlemanProbablePrimesImpl(immutable ushort lengthInBits)()
    if (lengthInBits == 2048u || lengthInBits == 3072u) // Step 1
    {
        step1:
            // Already handled by the template parameters

        step2:
            if (this.publicExponent <= ushort.max)
                throw new Exception("Public exponent too small.");
            // The "too large" check does not have to be done, since a size_t cannot be 2^256.

        // TODO: Document where these values come from.
        step3:
            static if (lengthInBits == 2048u)
                immutable ushort securityStrength = 112u;
            else static if (lengthInBits == 3072u)
                immutable ushort securityStrength = 128u;
            else assert(0u);

            CSPRNG rng = new CSPRNG(); // TODO: Make getBytes() const, so this can be const

        /*
            Step #4 creates the large prime, P. First, a large random number is
            generated. Then, if it is even, 1 is added to it to make it odd.
            Then, it is checked to make sure it is large enough, since a number
            generated from random bytes could have a lot of leading zeroes. Then,
            it is evaluated for coprimality with the public exponent. Finally, if
            it has passed all of those checks, a Rabin-Miller Probablistic Primality
            Test is performed on that number to determine if it is _probably_ prime.
            The variable i tracks how many iterations have passed, and the loop gives
            up if i exceeds a threshold specified by FIPS 186-4.
        */
        step4:
            step4_1:
                size_t i = 0u; // This is just used to make sure there is no infinite loop.

            /*
                Since the BigInt constructor does not accept bytes directly, we
                have to convert bytes to hexadecimal, then supply them to the
                constructor.

                Note that it is possible for random BigInts generated
                in this fashion to have leading null bytes, which is addressed
                in step #4.4.

                Also note that lengthInBits is divided by 16, because
                we have to divide by 8 to get the number of bytes we want, then we
                have to divide by 2 more to get a value of P big enough that, when
                multiplied with a similar-sized Q, we get a modulus, N, of the
                desired length in bits.
            */
            step4_2:
                BigInt p = BigInt("0x" ~ bytesToHex(cast(ubyte[]) rng.getBytes(lengthInBits / 16u)));

            // This step makes P odd.
            step4_3:
                if (!(p % 2)) p++;

            /*
                This step ensures that P is not too small. Since the random BigInt
                we are using was generated purely from random bytes, it is possible
                that it starts with leading null bytes. These checks below recreate
                P if P is too small. The value chosen for this check is not my
                choice--it is specified by FIPS 186-4, section B.3.3.
            */
            step4_4:
                BigInt halfMaxedP = (BigInt(2u) ^^ ((lengthInBits / 2u) - 1u));
                // Dividing by 1000, then multiplying by 1414 is *sqrt(2).
                if (p < ((halfMaxedP / 1000u) * 1414u)) goto step4_2;

            /*
                This step tests for coprimality of P and e. If P is coprime
                with e, we run several iterations of the Miller-Rabin
                Probabilistic Primality Test on P to ascertain that it is
                _most likely_ prime.
            */
            step4_5:
                if (greatestCommonDenominator((p - 1u), BigInt(this.publicExponent)) == 1)
                {
                    step4_5_1:
                    step4_5_2:
                        /*
                            See FIPS 186-4, Section C.3, Table C-2.
                            This gives a probability of 2^-112 that P is
                            actually composite when the test says it is prime.
                        */
                        if (millerRabinProbabilisticPrimalityTest(p, 5u))
                            goto step5;
                }

            step4_6:
                i++;

            /*
                This step exits the method if too many failed attempts at finding
                a large probable prime have failed. Note that the failure of the
                check for coprimality between P and e in step #4.5 is the only
                place that definitely results in an increment to i.
            */
            step4_7:
                if (i >= (5u * (lengthInBits / 2u)))
                    throw new Exception("Gave up trying to find a prime #1.");
                else
                    goto step4_2;

        /*
            Step 5 generates the large prime, Q. This only differs from step 4 in
            that it introduces another check to ensure that P and Q are not _too_
            similar.
        */
        step5:
            step5_1:
                i = 0u;

            /*
                Since the BigInt constructor does not accept bytes directly, we
                have to convert bytes to hexadecimal, then supply them to the
                constructor.

                Note that it is possible for random BigInts generated
                in this fashion to have leading null bytes, which is addressed
                in step #5.5.

                Also note that lengthInBits is divided by 16, because
                we have to divide by 8 to get the number of bytes we want, then we
                have to divide by 2 more to get a value of Q big enough that, when
                multiplied with a similar-sized P, we get a modulus, N, of the
                desired length in bits.
            */
            step5_2:
                BigInt q = BigInt("0x" ~ bytesToHex(cast(ubyte[]) rng.getBytes(lengthInBits / 16u)));

            // This step makes Q odd.
            step5_3:
                if (!(q % 2)) q++;

            /*
                This step ensures that P and Q are not _too_ similar. Since there
                is no absolute value operator for BigInt, we have to determine it
                the hard way, conditionally evaluation one condition if P is
                greater than Q, and another if Q is greater than P. The values
                chosen from this step were not my choice--they are specified in
                FIPS 186-4, section B.3.3.
            */
            step5_4:
                if
                ( // The following two lines are necessary, since there is no abs() for BigInt.
                    (p > q && ((p - q) <= (BigInt(2u) ^^ ((lengthInBits / 2u) - 100u)))) ||
                    (q > p && ((q - p) <= (BigInt(2u) ^^ ((lengthInBits / 2u) - 100u))))
                )
                    goto step5_2;

            /*
                This step ensures that Q is not too small. Since the random BigInt
                we are using was generated purely from random bytes, it is possible
                that it starts with leading null bytes. These checks below recreate
                Q if Q is too small. The value chosen for this check is not my
                choice--it is specified by FIPS 186-4, section B.3.3.
            */
            step5_5:
                BigInt halfMaxedQ = (BigInt(2u) ^^ ((lengthInBits / 2u) - 1u));
                // Dividing by 1000, then multiplying by 1414 is *sqrt(2).
                if (q < ((halfMaxedQ / 1000u) * 1414u)) goto step5_2;

            /*
                This step tests for coprimality of Q and e. If Q is coprime
                with e, we run several iterations of the Miller-Rabin
                Probabilistic Primality Test on Q to ascertain that it is
                _most likely_ prime.
            */
            step5_6:
                if (greatestCommonDenominator((q - BigInt(1u)), BigInt(this.publicExponent)) == BigInt(1u))
                {
                    step5_6_1:
                    step5_6_2:
                        /*
                            See FIPS 186-4, Section C.3, Table C-2.
                            This gives a probability of 2^-112 that Q is
                            actually composite when the test says it is prime.
                        */
                        if (millerRabinProbabilisticPrimalityTest(q, 5u))
                            return [ p, q ];
                }

            step5_7:
                i++;

            /*
                This step exits the method if too many failed attempts at finding
                a large probable prime have failed. Note that the failure of the
                check for coprimality between Q and e in step #5.6 is the only
                place that definitely results in an increment to i.
            */
            step5_8:
                if (i >= (5u * (lengthInBits / 2u)))
                    throw new Exception("Gave up trying to find prime #2.");
                else
                    goto step5_2;
    }

    /*
        I haven't figured out how to call a templated this, so for now, this
        has to accept a bool as a parameter dictating whether it generates
        3072-bit keys or 2048-bit keys.
    */
    public @system
    this (in ushort modulusLengthInBits = 3072u)
    {
        this.vers = RSAPrivateKeyVersion.twoPrime;

        /*
            Setting the public exponent must come before generating the
            probable primes, because their generation is dependent upon
            their coprimality with the public exponent, e. Also, the
            public exponent is set to 65537 with no option to change it
            for reasons described in documentation/design.md.
        */
        this.publicExponent = 65537u;

        /*
            Scoped so pq dies immediately after use.

            This library just outright ignores requests for stupidly-sized
            RSA keys, and just generates 2048-Bit keys unless a 3072-Bit key is
            requested. This is done in part to avoid fatal human errors, but
            also to ensure FIPS 186-4 compliance, which permits only 2048-Bit
            and 3072-Bit keys.
        */
        {
            BigInt[2] pq;
            if (modulusLengthInBits == 2048u)
                pq = generate2048BitRSAProbablePrimes();
            else
                pq = generate3072BitRSAProbablePrimes();

            this.prime1 = pq[0];
            this.prime2 = pq[1];
            pq = [ BigInt(0), BigInt(0) ]; // TODO: Confirm that this actually securely deletes.
        }

        this.modulus = (this.prime1 * this.prime2);
        this.privateExponent = modularInverse(BigInt(this.publicExponent), phi(this.prime1, this.prime2));
        this.exponent1 = (this.privateExponent % (this.prime1 - 1));
        this.exponent2 = (this.privateExponent % (this.prime2 - 1));
        this.coefficient = modularInverse(this.prime2, this.prime1);
    }

    public @system
    BigInt encrypt (BigInt plaintext) const
    {
        return modpow(plaintext, BigInt(this.publicExponent), this.modulus);
    }

    public @system
    BigInt decrypt (BigInt ciphertext) const
    {
        return modpow(ciphertext, this.privateExponent, this.modulus);
    }

    public @system
    void fromBytes (in ubyte[] bytes)
    {
        DERElement rsaPrivateKeyElement = new DERElement(bytes);
        // FIXME: This is where I left off.
        // FIXME: This depends upon the ability to get a BigInt out of a DERElement.
    }

    /**
        From $(LINK https://tools.ietf.org/html/rfc3447, RFC3447):

        $(PRE
            RSAPrivateKey ::= SEQUENCE {
                version           Version,
                modulus           INTEGER,  -- n
                publicExponent    INTEGER,  -- e
                privateExponent   INTEGER,  -- d
                prime1            INTEGER,  -- p
                prime2            INTEGER,  -- q
                exponent1         INTEGER,  -- d mod (p-1)
                exponent2         INTEGER,  -- d mod (q-1)
                coefficient       INTEGER,  -- (inverse of q) mod p
                otherPrimeInfos   OtherPrimeInfos OPTIONAL }

            OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
        )
    */
    public @property @system
    ubyte[] toBytes() const
    {
        version (LittleEndian) import std.algorithm.mutation : reverse;
        DERElement versionElement = new DERElement();
        versionElement.tagNumber = ASN1UniversalType.integer;
        versionElement.integer = cast(byte) RSAPrivateKeyVersion.twoPrime;

        DERElement modulusElement = new DERElement();
        modulusElement.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) modulusElement.value = bigintToBytes(this.modulus);
        version (LittleEndian) modulusElement.value = reverse(bigintToBytes(this.modulus));

        DERElement publicExponentElement = new DERElement();
        publicExponentElement.tagNumber = ASN1UniversalType.integer;
        publicExponentElement.integer = cast(long) this.publicExponent;

        DERElement privateExponentElement = new DERElement();
        privateExponentElement.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) privateExponentElement.value = bigintToBytes(this.privateExponent);
        version (LittleEndian) privateExponentElement.value = reverse(bigintToBytes(this.privateExponent));

        DERElement prime1Element = new DERElement();
        prime1Element.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) prime1Element.value = bigintToBytes(this.prime1);
        version (LittleEndian) prime1Element.value = reverse(bigintToBytes(this.prime1));

        DERElement prime2Element = new DERElement();
        prime2Element.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) prime2Element.value = bigintToBytes(this.prime2);
        version (LittleEndian) prime2Element.value = reverse(bigintToBytes(this.prime2));

        DERElement exponent1Element = new DERElement();
        exponent1Element.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) exponent1Element.value = bigintToBytes(this.exponent1);
        version (LittleEndian) exponent1Element.value = reverse(bigintToBytes(this.exponent1));

        DERElement exponent2Element = new DERElement();
        exponent2Element.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) exponent2Element.value = bigintToBytes(this.exponent2);
        version (LittleEndian) exponent2Element.value = reverse(bigintToBytes(this.exponent2));

        DERElement coefficientElement = new DERElement();
        coefficientElement.tagNumber = ASN1UniversalType.integer;
        version (BigEndian) coefficientElement.value = bigintToBytes(this.coefficient);
        version (LittleEndian) coefficientElement.value = reverse(bigintToBytes(this.coefficient));

        if (this.vers == RSAPrivateKeyVersion.multiPrime)
        {
            DERElement[] otherPrimeInfoSequence;
            foreach (otherPrimeInfo; this.otherPrimeInfos)
            {
                DERElement opiPrimeElement = new DERElement();
                opiPrimeElement.tagNumber = ASN1UniversalType.integer;
                version (BigEndian) opiPrimeElement.value = toBytes(otherPrimeInfo.prime);
                version (LittleEndian) opiPrimeElement.value = reverse(bigintToBytes(otherPrimeInfo.prime));

                DERElement opiExponentElement = new DERElement();
                opiExponentElement.tagNumber = ASN1UniversalType.integer;
                opiExponentElement.integer = cast(long) otherPrimeInfo.exponent;

                DERElement opiCoefficientElement = new DERElement();
                opiCoefficientElement.tagNumber = ASN1UniversalType.integer;
                version (BigEndian) opiCoefficientElement.value = toBytes(otherPrimeInfo.coefficient);
                version (LittleEndian) opiCoefficientElement.value = reverse(bigintToBytes(otherPrimeInfo.coefficient));

                DERElement otherPrimeInfoElement = new DERElement();
                otherPrimeInfoElement.tagNumber = ASN1UniversalType.sequence;
                otherPrimeInfoElement.sequence = [
                    opiPrimeElement,
                    opiExponentElement,
                    opiCoefficientElement
                ];

                otherPrimeInfoSequence ~= otherPrimeInfoElement;
            }

            DERElement otherPrimeInfosElement = new DERElement();
            otherPrimeInfosElement.tagNumber = ASN1UniversalType.sequence;
            otherPrimeInfosElement.sequence = otherPrimeInfoSequence;

            DERElement rsaPrivateKeyElement = new DERElement();
            rsaPrivateKeyElement.tagNumber = ASN1UniversalType.sequence;
            rsaPrivateKeyElement.sequence = [
                versionElement,
                modulusElement,
                publicExponentElement,
                privateExponentElement,
                prime1Element,
                prime2Element,
                exponent1Element,
                exponent2Element,
                coefficientElement,
                otherPrimeInfosElement
            ];
            return rsaPrivateKeyElement.toBytes;
        }

        DERElement rsaPrivateKeyElement = new DERElement();
        rsaPrivateKeyElement.tagNumber = ASN1UniversalType.sequence;
        rsaPrivateKeyElement.sequence = [
            versionElement,
            modulusElement,
            publicExponentElement,
            privateExponentElement,
            prime1Element,
            prime2Element,
            exponent1Element,
            exponent2Element,
            coefficientElement
        ];
        return rsaPrivateKeyElement.toBytes;
    }

    public @property @safe nothrow
    RSAPublicKey publicKey() const
    {
        return new RSAPublicKey(this.modulus, this.publicExponent);
    }

    public @safe @nogc nothrow
    ubyte[] opCast(T : ubyte[])() const
    {
        return this.toBytes;
    }

    public @safe @nogc nothrow
    RSAPublicKey opCast(T : RSAPublicKey)() const
    {
        return this.publicKey();
    }
}

///
public alias RSAPrivateKeyOtherPrimeInfo = RivestShamirAdlemanPrivateKeyOtherPrimeInfo;
/**
    OtherPrimeInfo ::= SEQUENCE {
        prime             INTEGER,  -- ri
        exponent          INTEGER,  -- di
        coefficient       INTEGER } -- ti
*/
public
struct RivestShamirAdlemanPrivateKeyOtherPrimeInfo
{
    public BigInt prime;
    public uint exponent;
    public BigInt coefficient;
}

/*
    Yes, I know this could have been a struct instead, but I made it a class so
    that, programmatically, it does not have to be handled differently from an
    RSAPrivateKey.
*/
///
public alias RSAPublicKey = RivestShamirAdlemanPublicKey;
/*
    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }
*/
public
class RivestShamirAdlemanPublicKey
{
    public BigInt modulus;
    public uint publicExponent;

    public @safe @nogc nothrow
    this (in BigInt modulus, in uint publicExponent)
    {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    public @system
    BigInt encrypt (BigInt plaintext) const
    {
        return modpow(plaintext, BigInt(this.publicExponent), this.modulus);
    }

    // NOTE: signedBytes should typically be a hash of the thing that is signed; not the thing itself.
    public @system
    bool checkSignature (in ubyte[] signedBytes, in ubyte[] signatureBytes)
    {
        BigInt signature = BigInt("0x" ~ bytesToHex(signatureBytes));
        BigInt signed = BigInt("0x" ~ bytesToHex(signedBytes));
        return (modpow(signature, BigInt(this.publicExponent), this.modulus) == signed);
    }
}

/*
    Source: http://www.c-sharpcorner.com/UploadFile/75a48f/rsa-algorithm-with-C-Sharp2/

    Getting D:
        (d * e) = 1 mod Phi(N)
        https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
        "A modular multiplicative inverse of a modulo m can be found by using the extended Euclidean algorithm."
        https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
        "The multiplicative inverse of “a modulo m” exists if and only if a and m are relatively prime (i.e., if gcd(a, m) = 1)."

    https://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa
    Generating the primes, P and Q:
        Fermat's Little Theorem:
            a^(p-1) = 1 (mod p)
            If the equality does not hold for a value of a,
            then p is composite.
            Choose a number a, where 1 < a < p-1.
    Source: https://crypto.stackexchange.com/questions/71/how-can-i-generate-large-prime-numbers-for-rsa#79
*/
void main()
{
    import std.stdio : stdout;
    // const BigInt plaintext = BigInt(27);
    // RSAPrivateKey privkey = new RSAPrivateKey(2048u);
    // BigInt ciphertext = privkey.encrypt(plaintext);
    // assert(privkey.decrypt(ciphertext) == plaintext);
    // stdout.rawWrite(privkey.toBytes);


    // RSAPrivateKey privkey = new RSAPrivateKey(2048u);
    // public RSAPrivateKeyVersion vers;
    // public BigInt modulus;
    // public uint publicExponent;
    // privkey.privateExponent;
    // privkey.prime1;
    // privkey.prime2;
    // privkey.exponent1;
    // privkey.exponent2;
    // privkey.coefficient;
    // public RSAPrivateKeyOtherPrimeInfo[] otherPrimeInfos;
}