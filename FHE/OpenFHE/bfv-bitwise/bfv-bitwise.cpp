#include "openfhe.h"
#include <iostream>
#include <vector>
#include <numeric>
#include <algorithm>
#include <chrono>
#include <cstdlib>
using namespace lbcrypto;
using namespace std;

struct Stats {
    double enc = 0, dec = 0, cmp = 0, swp = 0, sort = 0;
};

vector<vector<Ciphertext<DCRTPoly>>> vectorEncrypt(
    CryptoContext<DCRTPoly> cc,
    const PublicKey<DCRTPoly>& publicKey,
    const vector<int>& v,
    int bitWidth
) {
    vector<vector<Ciphertext<DCRTPoly>>> encryptedBitmap(v.size(), vector<Ciphertext<DCRTPoly>>(bitWidth));
    for (int i=0; i<v.size(); i++) {
        for (int j=0; j<bitWidth; j++) {
            int64_t bit = (v[i] >> j) & 1;
            Plaintext plaintext = cc->MakeCoefPackedPlaintext({bit});
            encryptedBitmap[i][bitWidth-1-j] = cc->Encrypt(publicKey, plaintext);
        }
    }
    return encryptedBitmap;
}

vector<int> vectorDecrypt(
    CryptoContext<DCRTPoly> cc,
    const PrivateKey<DCRTPoly>& secretKey,
    const vector<vector<Ciphertext<DCRTPoly>>>& encryptedBitmap,
    int bitWidth
) {
    vector<int> v;
    for (int i=0; i<encryptedBitmap.size(); i++) {
        int num = 0;
        for (int j=0; j<bitWidth; j++) {
            Plaintext plaintext;
            cc->Decrypt(secretKey, encryptedBitmap[i][j], &plaintext);
            plaintext->SetLength(1);
            int bit = plaintext->GetCoefPackedValue()[0];
            num = (num << 1) | bit;
        }
        v.push_back(num);
    }
    return v;
}

Ciphertext<DCRTPoly> compare(
    CryptoContext<DCRTPoly> cc,
    const vector<Ciphertext<DCRTPoly>>& num1,
    const vector<Ciphertext<DCRTPoly>>& num2,
    const Ciphertext<DCRTPoly>& cZero,
    const Ciphertext<DCRTPoly>& cOne
) {
    Plaintext pTwo = cc->MakeCoefPackedPlaintext({2});
    Ciphertext<DCRTPoly> less = cZero;
    Ciphertext<DCRTPoly> equal = cOne;
    for (int i=0; i<num1.size(); i++) {
        Ciphertext<DCRTPoly> a = num1[i];
        Ciphertext<DCRTPoly> b = num2[i];

        // currentLess = (1 - a) * b * equal
        Ciphertext<DCRTPoly> currentLess = cc->EvalMult(cc->EvalMult(cc->EvalSub(cOne, a), b), equal);

        // less = less + currentLess - less * currentLess
        less = cc->EvalSub(cc->EvalAdd(less, currentLess), cc->EvalMult(less, currentLess));

        // xorAB = a + b - 2 * a * b
        Ciphertext<DCRTPoly> xorAB = cc->EvalSub(cc->EvalAdd(a, b), cc->EvalMult(cc->EvalMult(a, b), pTwo));

        // notXORAB = 1 - xorAB
        Ciphertext<DCRTPoly> notXORAB = cc->EvalSub(cOne, xorAB);

        // equal = equal * notXORAB
        equal = cc->EvalMult(equal, notXORAB);
    }
    return less;
}

pair<vector<Ciphertext<DCRTPoly>>, vector<Ciphertext<DCRTPoly>>> swap(
    CryptoContext<DCRTPoly> cc,
    const vector<Ciphertext<DCRTPoly>>& num1,
    const vector<Ciphertext<DCRTPoly>>& num2,
    const Ciphertext<DCRTPoly>& less,
    const Ciphertext<DCRTPoly>& cOne
) {
    vector<Ciphertext<DCRTPoly>> small(num1.size());
    vector<Ciphertext<DCRTPoly>> large(num1.size());
    Ciphertext<DCRTPoly> notLess = cc->EvalSub(cOne, less);
    for (int i=0; i<num1.size(); i++) {
        // small = (1 - less) * b + (less) * a
        small[i] = cc->EvalAdd(cc->EvalMult(notLess, num2[i]), cc->EvalMult(less, num1[i]));

        // large = (1 - less) * a + (less) * b
        large[i] = cc->EvalAdd(cc->EvalMult(notLess, num1[i]), cc->EvalMult(less, num2[i]));
    }
    return {small, large};
}

void bubbleSort(
    CryptoContext<DCRTPoly> cc,
    vector<vector<Ciphertext<DCRTPoly>>>& encryptedBitmap,
    const Ciphertext<DCRTPoly>& cZero,
    const Ciphertext<DCRTPoly>& cOne,
    Stats& stats
) {
    for (int i=0; i<encryptedBitmap.size()-1; i++) {
        for (int j=0; j<encryptedBitmap.size()-i-1; j++) {

            auto startCmp = chrono::high_resolution_clock::now();
            Ciphertext<DCRTPoly> less = compare(cc, encryptedBitmap[j], encryptedBitmap[j+1], cZero, cOne);
            auto endCmp = chrono::high_resolution_clock::now();
            stats.cmp += (endCmp - startCmp).count() / 1e9;

            auto startSwap = chrono::high_resolution_clock::now();
            auto [small, large] = swap(cc, encryptedBitmap[j], encryptedBitmap[j+1], less, cOne);
            auto endSwap = chrono::high_resolution_clock::now();
            stats.swp += (endSwap - startSwap).count() / 1e9;

            encryptedBitmap[j] = small;
            encryptedBitmap[j+1] = large;
        }
    }
}

void insertionSort(
    CryptoContext<DCRTPoly> cc,
    vector<vector<Ciphertext<DCRTPoly>>>& encryptedBitmap,
    const Ciphertext<DCRTPoly>& cZero,
    const Ciphertext<DCRTPoly>& cOne,
    Stats& stats
) {
    for (int i=1; i<encryptedBitmap.size(); i++) {
        for (int j=i-1; j>=0; j--) {

            auto startCmp = chrono::high_resolution_clock::now();
            Ciphertext<DCRTPoly> less = compare(cc, encryptedBitmap[j], encryptedBitmap[j+1], cZero, cOne);
            auto endCmp = chrono::high_resolution_clock::now();
            stats.cmp += (endCmp - startCmp).count() / 1e9;

            auto startSwap = chrono::high_resolution_clock::now();
            auto [small, large] = swap(cc, encryptedBitmap[j], encryptedBitmap[j+1], less, cOne);
            auto endSwap = chrono::high_resolution_clock::now();
            stats.swp += (endSwap - startSwap).count() / 1e9;

            encryptedBitmap[j] = small;
            encryptedBitmap[j+1] = large;
        }
    }
}

Stats runFHEJobBenchmark(int N, int depth, string algo) {
    Stats stats;
    int bitWidth = ceil(log2(N));
    int plaintextModulus = 4;
    
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetStandardDeviation(3.2);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    Plaintext pZero = cc->MakeCoefPackedPlaintext({0});
    Plaintext pOne = cc->MakeCoefPackedPlaintext({1});
    Ciphertext<DCRTPoly> cZero = cc->Encrypt(keys.publicKey, pZero);
    Ciphertext<DCRTPoly> cOne = cc->Encrypt(keys.publicKey, pOne);

    // Random input
    vector<int> v(N);
    for (int i=0; i<N; i++) {
        v[i] = rand() % N;
    }

    cout << "Unsorted: ";
    for (auto x : v) {
        cout << x << " ";
    }
    cout << "  ->  ";

    // Encryption
    auto startEnc = chrono::high_resolution_clock::now();
    vector<vector<Ciphertext<DCRTPoly>>> encryptedBitmap = vectorEncrypt(cc, keys.publicKey, v, bitWidth);
    auto endEnc = chrono::high_resolution_clock::now();
    stats.enc += (endEnc - startEnc).count() / 1e9;

    // Sorting
    auto startSort = chrono::high_resolution_clock::now();
    if (algo == "bubble") {
        bubbleSort(cc, encryptedBitmap, cZero, cOne, stats);
    } else {
        insertionSort(cc, encryptedBitmap, cZero, cOne, stats);
    }
    auto endSort = chrono::high_resolution_clock::now();
    stats.sort += (endSort - startSort).count() / 1e9;

    // Decryption
    auto startDec = chrono::high_resolution_clock::now();
    vector<int> sorted = vectorDecrypt(cc, keys.secretKey, encryptedBitmap, bitWidth);
    auto endDec = chrono::high_resolution_clock::now();
    stats.dec += (endDec - startDec).count() / 1e9;

    cout << "Sorted: ";
    for (int x : sorted) {
        cout << x << " ";
    }
    cout << endl;

    cc.reset();
    return stats;
}

int main() {
    srand(time(NULL));
    int N, depth;
    cout << "Enter number of elements to sort: ";
    cin >> N;
    cout << "Enter depth: ";
    cin >> depth;

    for (string algo : {"bubble", "insertion"}) {
        cout << "===== Algorithm: " << algo << " =====" << endl;
        for (int i=1; i<=5; i++) {
            cout << "--- Run " << i << " ---" << endl;
            Stats s = runFHEJobBenchmark(N, depth, algo);
            cout << "Encryption:   " << s.enc << " sec\n";
            cout << "Decryption:   " << s.dec << " sec\n";
            cout << "Compare:      " << s.cmp << " sec\n";
            cout << "Swap:         " << s.swp << " sec\n";
            cout << "Sort Total:   " << s.sort << " sec\n";
            cout << endl;
        }
        cout << endl;
    }

    return 0;
}

