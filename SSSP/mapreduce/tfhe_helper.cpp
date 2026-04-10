#include "tfhe_helper.h"

using namespace std;

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
        // sum[i]  = a[i] XOR b[i] XOR carry
        LWECiphertext aXorB = cc.EvalBinGate(XOR, a[i], b[i]);
        sum[i] = cc.EvalBinGate(XOR, aXorB, carry);

        // carry = (a[i] AND b[i]) OR (carry AND (a[i] XOR b[i]))
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
        // borrow_out = (~a[i] & b[i]) | (~a[i] & borrow) | (b[i] & borrow)
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
    auto less  = encLessThan(cc, cZero, a, b); 
    auto notLess = cc.EvalNOT(less);

    EncInt result(BITWIDTH);
    for (int i=0; i<BITWIDTH; i++) {
        // result[i] = (less & a[i]) | (~less & b[i])
        result[i] = cc.EvalBinGate(OR, cc.EvalBinGate(AND, less, a[i]), cc.EvalBinGate(AND, notLess, b[i]));
    }
    return result;
}


void writeEncInt(HDFSWriter& w, EncInt& encVal) {
    uint32_t sz = encVal.size();
    w.write(sz);
    for (auto& ct : encVal) {
        ostringstream tmp;
        Serial::Serialize(ct, tmp, SerType::BINARY);
        const string& raw = tmp.str();
        uint32_t ctSz = raw.size();
        w.write(ctSz);
        w.write(raw.data(), ctSz);
    }
}

EncInt readEncInt(HDFSReader& r) {
    uint32_t sz;
    r.read(sz);
    EncInt encVal;
    encVal.reserve(sz);
    for (uint32_t i=0; i<sz; i++) {
        uint32_t ctSz;
        r.read(ctSz);
        string raw(ctSz, '\0');
        r.read(raw.data(), ctSz);
        istringstream tmp(raw);
        LWECiphertext ct;
        Serial::Deserialize(ct, tmp, SerType::BINARY);
        encVal.push_back(ct);
    }
    return encVal;
}

void writeEncEdge(HDFSWriter& w, EncEdge& e) {
    w.write(e.u);
    w.write(e.v);
    writeEncInt(w, e.w);
}

EncEdge readEncEdge(HDFSReader& r) {
    EncEdge e;
    r.read(e.u);
    r.read(e.v);
    e.w = readEncInt(r);
    return e;
}