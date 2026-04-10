#pragma once
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;
using EncInt = std::vector<Ciphertext<DCRTPoly>>;

struct EncEdge {
    int u, v;
    EncInt w;
};

constexpr int BITWIDTH = 8;
constexpr int INF_VAL = 50;

inline CryptoContext<DCRTPoly> makeBFVContext(int depth) {
    CCParams<CryptoContextBFVRNS> params;
    params.SetPlaintextModulus(4);
    params.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    params.SetMultiplicativeDepth(depth);
    params.SetStandardDeviation(3.2);
    params.SetKeySwitchTechnique(HYBRID);
    params.SetScalingModSize(60);
    auto cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

inline Ciphertext<DCRTPoly> encryptBit(
    CryptoContext<DCRTPoly>& cc,
    const PublicKey<DCRTPoly>& pk,
    int64_t bit) 
{
    return cc->Encrypt(pk, cc->MakeCoefPackedPlaintext({bit}));
}

// NOT(a, b) = 1 - a
inline Ciphertext<DCRTPoly> bfvNOT(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& cOne,
    const Ciphertext<DCRTPoly>& a)
{
    return cc->EvalSub(cOne, a);
}

// AND(a, b) = a * b
inline Ciphertext<DCRTPoly> bfvAND(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& a,
    const Ciphertext<DCRTPoly>& b)
{
    return cc->EvalMult(a, b);
}

// XOR(a, b) = a + b - 2*a*b
inline Ciphertext<DCRTPoly> bfvXOR(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& a,
    const Ciphertext<DCRTPoly>& b)
{
    Plaintext pTwo = cc->MakeCoefPackedPlaintext({2});
    return cc->EvalSub(cc->EvalAdd(a, b), cc->EvalMult(cc->EvalMult(a, b), pTwo));
}

// OR(a, b) = a + b - a*b
inline Ciphertext<DCRTPoly> bfvOR(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& a,
    const Ciphertext<DCRTPoly>& b)
{
    return cc->EvalSub(cc->EvalAdd(a, b), cc->EvalMult(a, b));
}


inline EncInt encryptInt(
    CryptoContext<DCRTPoly>& cc,
    const PublicKey<DCRTPoly>& pk,
    int num)
{
    EncInt encNum(BITWIDTH);
    for (int i=0; i<BITWIDTH; i++) {
        encNum[i] = encryptBit(cc, pk, (num >> i) & 1);
    }
    return encNum;
}

inline int decryptInt(
    CryptoContext<DCRTPoly>& cc,
    const PrivateKey<DCRTPoly>& sk,
    EncInt& enc)
{
    int num = 0;
    for (int i=0; i<BITWIDTH; i++) {
        Plaintext pt;
        cc->Decrypt(sk, enc[i], &pt);
        pt->SetLength(1);
        num |= (pt->GetCoefPackedValue()[0] & 1) << i;
    }
    return num;
}

/* Add two EncInt */
inline EncInt encAdd(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& cZero,
    EncInt& a,
    EncInt& b)
{
    EncInt sum(BITWIDTH);
    Ciphertext<DCRTPoly> carry = cZero;
    for (int i=0; i<BITWIDTH; i++) {
        // sum[i] = a[i] ^ b[i] ^ carry
        Ciphertext<DCRTPoly> aXorB = bfvXOR(cc, a[i], b[i]);
        sum[i] = bfvXOR(cc, aXorB, carry);

        // carry = (a[i] & b[i]) | (carry & (a[i] ^ b[i]))
        Ciphertext<DCRTPoly> aAndB  = bfvAND(cc, a[i], b[i]);
        Ciphertext<DCRTPoly> cAnd = bfvAND(cc, carry, aXorB);
        carry = bfvOR(cc, aAndB, cAnd);
    }
    return sum;
}

/* Return 1 if a < b */
inline Ciphertext<DCRTPoly> encLessThan(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& cZero,
    const Ciphertext<DCRTPoly>& cOne,
    EncInt& a,
    EncInt& b)
{
    Ciphertext<DCRTPoly> borrow = cZero;
    for (int i=0; i<BITWIDTH; i++) {
        // borrow = (~a[i] & b[i]) | (~a[i] & borrow) | (b[i] & borrow)
        Ciphertext<DCRTPoly> notA = bfvNOT(cc, cOne, a[i]);
        Ciphertext<DCRTPoly> t1 = bfvAND(cc, notA, b[i]);
        Ciphertext<DCRTPoly> t2 = bfvAND(cc, notA, borrow);
        Ciphertext<DCRTPoly> t3 = bfvAND(cc, b[i], borrow);
        borrow = bfvOR(cc, bfvOR(cc, t1, t2), t3);
    }
    return borrow;
}

/* Return min(a, b) */
inline EncInt encMin(
    CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& cZero,
    const Ciphertext<DCRTPoly>& cOne,
    EncInt& a,
    EncInt& b)
{
    Ciphertext<DCRTPoly> less = encLessThan(cc, cZero, cOne, a, b);
    Ciphertext<DCRTPoly> notLess = bfvNOT(cc, cOne, less);
    EncInt result(BITWIDTH);
    for (int i=0; i<BITWIDTH; i++) {
        // result[i] = (less & a[i]) | (~less & b[i])
        result[i] = bfvOR(cc, bfvAND(cc, less, a[i]), bfvAND(cc, notLess, b[i]));
    }
    return result;
}