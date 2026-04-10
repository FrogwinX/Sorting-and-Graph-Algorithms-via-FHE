#include "fhe_helper.h"

EncInt encryptInt(BinFHEContext& cc, LWEPrivateKey& sk, int num) {
    EncInt encNum;
    encNum.reserve(BITWIDTH);
    for (int i=0; i<BITWIDTH; i++) {
        encNum.push_back(cc.Encrypt(sk, (num >> i) & 1, FRESH, 4)); // p = 4 for binary gate operations in OpenFHE (BinFHE)
    }
    return encNum;
}

int decryptInt(BinFHEContext& cc, LWEPrivateKey& sk, EncInt& encNum) {
    int num = 0;
    for (int i=0; i<BITWIDTH; i++) {
        LWEPlaintext bit;
        cc.Decrypt(sk, encNum[i], &bit);
        num |= (bit << i);
    }
    return num;
}

/* Add two EncInt */
EncInt encAdd(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b) {
    EncInt sum(BITWIDTH);
    LWECiphertext carry = cZero;
    for (int i=0; i<BITWIDTH; i++) {
        // sum[i] = a[i] ^ b[i] ^ carry
        LWECiphertext aXorB = cc.EvalBinGate(XOR, a[i], b[i]);
        sum[i] = cc.EvalBinGate(XOR, aXorB, carry);

        // carry = (a[i] & b[i]) | (carry & (a[i] ^ b[i]))
        LWECiphertext aAndB = cc.EvalBinGate(AND, a[i], b[i]);
        LWECiphertext cAnd = cc.EvalBinGate(AND, carry, aXorB);
        carry = cc.EvalBinGate(OR, aAndB, cAnd);
    }
    return sum;
}

/* Return 1 if a < b */
LWECiphertext encLessThan(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b) {
    LWECiphertext borrow = cZero;
    for (int i=0; i<BITWIDTH; i++) {
        // borrow = (~a[i] & b[i]) | (~a[i] & borrow) | (b[i] & borrow)
        LWECiphertext notA = cc.EvalNOT(a[i]);
        LWECiphertext t1 = cc.EvalBinGate(AND, notA, b[i]);
        LWECiphertext t2 = cc.EvalBinGate(AND, notA, borrow);
        LWECiphertext t3 = cc.EvalBinGate(AND, b[i], borrow);
        borrow = cc.EvalBinGate(OR, cc.EvalBinGate(OR, t1, t2), t3);
    }
    return borrow;
}

/* Return min(a, b) */
EncInt encMin(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b) {
    LWECiphertext less = encLessThan(cc, cZero, a, b); 
    LWECiphertext notLess = cc.EvalNOT(less);

    EncInt result(BITWIDTH);
    for (int i=0; i<BITWIDTH; i++) {
        // result[i] = (less & a[i]) | (~less & b[i])
        result[i] = cc.EvalBinGate(OR, cc.EvalBinGate(AND, less, a[i]), cc.EvalBinGate(AND, notLess, b[i]));
    }
    return result;
}