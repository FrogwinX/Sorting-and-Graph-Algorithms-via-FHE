#ifndef TFHE_HELPER_H
#define TFHE_HELPER_H

#include "openfhe.h"
#include "hdfs_helper.h"
#include <bits/stdc++.h>

using namespace lbcrypto;
using EncInt = std::vector<LWECiphertext>;

struct EncEdge {
    int u, v;
    EncInt w;
};

constexpr int BITWIDTH = 8;

// void initContext();
// BinFHEContext& getContext();
// LWEPrivateKey& getSecretKey();
// LWECiphertext& getChiphertextZero();

EncInt encryptInt(BinFHEContext& cc, LWEPrivateKey& sk, int num);
int decryptInt(BinFHEContext& cc, LWEPrivateKey& sk, EncInt& encNum);
EncInt encAdd(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b);
LWECiphertext encLessThan(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b);
EncInt encMin(BinFHEContext& cc, LWECiphertext& cZero, EncInt& a, EncInt& b);

void writeEncInt(HDFSWriter& w, EncInt& encVal);
EncInt readEncInt(HDFSReader& r);
void writeEncEdge(HDFSWriter& w, EncEdge& e);
EncEdge readEncEdge(HDFSReader& r);

#endif