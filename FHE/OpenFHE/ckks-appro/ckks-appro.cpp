#include "openfhe.h"
#include <iostream>
#include <vector>
#include <numeric>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
using namespace lbcrypto;
using namespace std;

struct Stats {
    double enc = 0, dec = 0, cmp = 0, swp = 0, sort = 0;
};

vector<Ciphertext<DCRTPoly>> vectorEncrypt(
    CryptoContext<DCRTPoly> cc,
    const PublicKey<DCRTPoly>& publicKey,
    const vector<double>& v
) {
    vector<Ciphertext<DCRTPoly>> encrypted(v.size());
    for (int i=0; i<v.size(); i++) {
        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(vector<double>{v[i]});
        encrypted[i] = cc->Encrypt(publicKey, plaintext);
    }
    return encrypted;
}

vector<double> vectorDecrypt(
    CryptoContext<DCRTPoly> cc,
    const PrivateKey<DCRTPoly>& secretKey,
    const vector<Ciphertext<DCRTPoly>>& encrypted
) {
    vector<double> v;
    for (auto& ciphertext : encrypted) {
        Plaintext plaintext;
        cc->Decrypt(secretKey, ciphertext, &plaintext);
        plaintext->SetLength(1);
        v.push_back(plaintext->GetRealPackedValue()[0]);
    }
    return v;
}


// Approximate compare function using f3/g3 polynomials
Ciphertext<DCRTPoly> compare(
    CryptoContext<DCRTPoly> cc,
    const Ciphertext<DCRTPoly>& num1,
    const Ciphertext<DCRTPoly>& num2,
    double scale,
    int df = 1,
    int dg = 1
) {
    // Normalize difference (num1 - num2)
    Ciphertext<DCRTPoly> diff = cc->EvalSub(num1, num2);
    Plaintext pScale = cc->MakeCKKSPackedPlaintext(vector<double>{1.0 / scale});
    Ciphertext<DCRTPoly> diffNorm = cc->EvalMult(diff, pScale);

    // g3 polynomial
    function g3 = [&](const Ciphertext<DCRTPoly>& x) -> Ciphertext<DCRTPoly> {
        Plaintext p7 = cc->MakeCKKSPackedPlaintext(vector<double>{-12860.0 / 1024});
        Plaintext p5 = cc->MakeCKKSPackedPlaintext(vector<double>{25614.0 / 1024});
        Plaintext p3 = cc->MakeCKKSPackedPlaintext(vector<double>{-16577.0 / 1024});
        Plaintext p1 = cc->MakeCKKSPackedPlaintext(vector<double>{4589.0 / 1024});

        Ciphertext<DCRTPoly> x2 = cc->EvalMult(x, x);
        Ciphertext<DCRTPoly> g = cc->EvalMult(p7, x2);
        g = cc->EvalAdd(g, p5);
        g = cc->EvalMult(g, x2);
        g = cc->EvalAdd(g, p3);
        g = cc->EvalMult(g, x2);
        g = cc->EvalAdd(g, p1);
        return cc->EvalMult(g, x);
    };

    // f3 polynomial
    function f3 = [&](const Ciphertext<DCRTPoly>& x) -> Ciphertext<DCRTPoly> {
        Plaintext p7 = cc->MakeCKKSPackedPlaintext(vector<double>{-5.0 / 16});
        Plaintext p5 = cc->MakeCKKSPackedPlaintext(vector<double>{21.0 / 16});
        Plaintext p3 = cc->MakeCKKSPackedPlaintext(vector<double>{-35.0 / 16});
        Plaintext p1 = cc->MakeCKKSPackedPlaintext(vector<double>{35.0 / 16});

        Ciphertext<DCRTPoly> x2 = cc->EvalMult(x, x);
        Ciphertext<DCRTPoly> f = cc->EvalMult(p7, x2);
        f = cc->EvalAdd(f, p5);
        f = cc->EvalMult(f, x2);
        f = cc->EvalAdd(f, p3);
        f = cc->EvalMult(f, x2);
        f = cc->EvalAdd(f, p1);
        return cc->EvalMult(f, x);
    };

    // Apply g3 dg times
    Ciphertext<DCRTPoly> more = diffNorm;
    for (int i=0; i<dg; i++) {
        more = g3(more);
    }

    // Apply f3 df times
    for (int i=0; i<df; i++) {
        more = f3(more);
    }

    // Map [-1,1] -> [0,1]
    Plaintext pOne = cc->MakeCKKSPackedPlaintext(vector<double>{1.0});
    more = cc->EvalAdd(more, pOne);
    more = cc->EvalMult(more, cc->MakeCKKSPackedPlaintext(vector<double>{0.5}));

    return more;
}

pair<Ciphertext<DCRTPoly>, Ciphertext<DCRTPoly>> swap(
    CryptoContext<DCRTPoly> cc,
    const Ciphertext<DCRTPoly>& num1,
    const Ciphertext<DCRTPoly>& num2,
    const Ciphertext<DCRTPoly>& more
) {
    Plaintext pOne = cc->MakeCKKSPackedPlaintext(vector<double>{1.0});
    Ciphertext<DCRTPoly> notMore = cc->EvalSub(pOne, more);
    // small = (1 - more) * a + (more) * b
    Ciphertext<DCRTPoly> small = cc->EvalAdd(cc->EvalMult(notMore, num1), cc->EvalMult(more, num2));
    
    // large = (1 - more) * b + (more) * a
    Ciphertext<DCRTPoly> large = cc->EvalAdd(cc->EvalMult(notMore, num2), cc->EvalMult(more, num1));
    return {small, large};
}

void bubbleSort(
    CryptoContext<DCRTPoly> cc,
    vector<Ciphertext<DCRTPoly>>& encrypted,
    double scale,
    Stats& stats,
    int df = 1,
    int dg = 1
) {
    for (int i=0; i<encrypted.size()-1; i++) {
        for (int j=0; j<encrypted.size()-i-1; j++) {
            
            auto startCmp = chrono::high_resolution_clock::now();
            Ciphertext<DCRTPoly> more = compare(cc, encrypted[j], encrypted[j+1], scale, df, dg);
            auto endCmp = chrono::high_resolution_clock::now();
            stats.cmp += (endCmp - startCmp).count() / 1e9;

            auto startSwap = chrono::high_resolution_clock::now();
            auto [small, large] = swap(cc, encrypted[j], encrypted[j+1], more);
            auto endSwap = chrono::high_resolution_clock::now();
            stats.swp += (endSwap - startSwap).count() / 1e9;

            encrypted[j] = small;
            encrypted[j + 1] = large;
        }
    }
}

void insertionSort(
    CryptoContext<DCRTPoly> cc,
    vector<Ciphertext<DCRTPoly>>& encrypted,
    double scale,
    Stats& stats,
    int df = 1,
    int dg = 1
) {
    for (int i=1; i<encrypted.size(); i++) {
        for (int j=i-1; j>=0; j--) {

            auto startCmp = chrono::high_resolution_clock::now();
            Ciphertext<DCRTPoly> more = compare(cc, encrypted[j], encrypted[j+1], scale, df, dg);
            auto endCmp = chrono::high_resolution_clock::now();
            stats.cmp += (endCmp - startCmp).count() / 1e9;

            auto startSwap = chrono::high_resolution_clock::now();
            auto [small, large] = swap(cc, encrypted[j], encrypted[j+1], more);
            auto endSwap = chrono::high_resolution_clock::now();
            stats.swp += (endSwap - startSwap).count() / 1e9;

            encrypted[j] = small;
            encrypted[j+1] = large;
        }
    }
}

Stats runFHEJobBenchmark(int N, int depth, int ringDim, string algo) {
    Stats stats;

    // Random input
    vector<double> v(N);
    for (int i=0; i<N; i++) {
        v[i] = rand() % N;
    }

    cout << "Unsorted: ";
    for (auto x : v) cout << x << " ";
    cout << "  ->  ";

    double maxVal = *max_element(v.begin(), v.end());
    double scale = (maxVal == 0.0 ? 1.0 : maxVal);

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(40);
    parameters.SetRingDim(ringDim);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalAtIndexKeyGen(keys.secretKey, {1, -1});

    // Encryption
    auto startEnc = chrono::high_resolution_clock::now();
    vector<Ciphertext<DCRTPoly>> encrypted = vectorEncrypt(cc, keys.publicKey, v);
    auto endEnc = chrono::high_resolution_clock::now();
    stats.enc += (endEnc - startEnc).count() / 1e9;

    // Sorting
    auto startSort = chrono::high_resolution_clock::now();
    if (algo == "bubble") {
        bubbleSort(cc, encrypted, scale, stats);
    } else {
        insertionSort(cc, encrypted, scale, stats);
    }
    auto endSort = chrono::high_resolution_clock::now();
    stats.sort += (endSort - startSort).count() / 1e9;

    // Decryption
    auto startDec = chrono::high_resolution_clock::now();
    vector<double> decrypted = vectorDecrypt(cc, keys.secretKey, encrypted);
    for (auto& v : decrypted) {
        v = lround(v);
    }
    auto endDec = chrono::high_resolution_clock::now();
    stats.dec += (endDec - startDec).count() / 1e9;

    cout << "Sorted: ";
    for (auto x : decrypted) {
        cout << x << " ";
    }
    cout << endl;

    cc.reset();
    return stats;
}

int main() {
    srand(time(NULL));
    int N, depth, ringDim;
    cout << "Enter number of elements to sort: ";
    cin >> N;
    cout << "Enter depth: ";
    cin >> depth;
    cout << "Enter ringDim: ";
    cin >> ringDim;

    for (string algo : {"bubble", "insertion"}) {
        cout << "===== Algorithm: " << algo << " =====" << endl;
        for (int i=1; i<=1; i++) {
            cout << "--- Run " << i << " ---" << endl;
            Stats s = runFHEJobBenchmark(N, depth, ringDim, algo);
            cout << "Encryption:   " << s.enc << " sec\n";
            cout << "Decryption:   " << s.dec << " sec\n";
            cout << "Compare:      " << s.cmp << " sec\n";
            cout << "Swap:         " << s.swp << " sec\n";
            cout << "Sort Total:   " << s.sort << " sec\n";
            cout << endl;
        }
    }

    return 0;
}
