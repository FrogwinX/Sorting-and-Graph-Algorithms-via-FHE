#ifndef FHE_HELPER_H
#define FHE_HELPER_H

#include "openfhe.h"
#include <bits/stdc++.h>

using namespace lbcrypto;
using EncInt = std::vector<LWECiphertext>;

struct EncEdge {
    int u, v;
    EncInt w;
};

constexpr int BITWIDTH = 16;
constexpr int INF_VAL = 50000;

EncInt encryptInt(BinFHEContext& cc, LWEPrivateKey& sk, int num);
int decryptInt(BinFHEContext& cc, LWEPrivateKey& sk, EncInt& encNum);
EncInt encAdd(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b);
LWECiphertext encLessThan(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b);
EncInt encMin(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b);

#endif