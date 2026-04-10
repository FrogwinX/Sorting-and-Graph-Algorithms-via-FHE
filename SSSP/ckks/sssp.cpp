#include "openfhe.h"
#include <iostream>
#include <vector>
#include <functional>

using namespace lbcrypto;
using namespace std;

Ciphertext<DCRTPoly> compare(
    CryptoContext<DCRTPoly> cc,
    const Ciphertext<DCRTPoly>& num1,
    const Ciphertext<DCRTPoly>& num2,
    double scale, 
    int df = 1, 
    int dg = 1
) {
    Ciphertext<DCRTPoly> diff = cc->EvalSub(num1, num2);
    Plaintext pScale = cc->MakeCKKSPackedPlaintext(vector<double>{1.0 / scale});
    Ciphertext<DCRTPoly> diffNorm = cc->EvalMult(diff, pScale);

    auto g3 = [&](const Ciphertext<DCRTPoly>& x) {
        Plaintext p7 = cc->MakeCKKSPackedPlaintext(vector<double>{-12860.0 / 1024});
        Plaintext p5 = cc->MakeCKKSPackedPlaintext(vector<double>{ 25614.0 / 1024});
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

    auto f3 = [&](const Ciphertext<DCRTPoly>& x) {
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

    Ciphertext<DCRTPoly> more = diffNorm;
    for (int i=0; i<dg; i++) more = g3(more);
    for (int i=0; i<df; i++) more = f3(more);

    Plaintext pOne = cc->MakeCKKSPackedPlaintext(vector<double>{1.0});
    more = cc->EvalAdd(more, pOne);
    more = cc->EvalMult(more, cc->MakeCKKSPackedPlaintext(vector<double>{0.5}));
    return more;
}

Ciphertext<DCRTPoly> encMin(
    CryptoContext<DCRTPoly> cc,
    const Ciphertext<DCRTPoly>& a,
    const Ciphertext<DCRTPoly>& b,
    double scale
) {
    Ciphertext<DCRTPoly> more = compare(cc, a, b, scale);
    Plaintext pOne = cc->MakeCKKSPackedPlaintext(vector<double>{1.0});
    Ciphertext<DCRTPoly> less = cc->EvalSub(pOne, more);
    return cc->EvalAdd(cc->EvalMult(less, a), cc->EvalMult(more, b));
}

struct EncEdge {
    int u, v;
    Ciphertext<DCRTPoly> w;
};

int main() {
    int V = 5;
    vector<vector<int>> edges = {
        {2, 3, 3},
        {1, 2, 2},
        {0, 1, 1},
        {0, 3, 10}
    };
    int src = 0;

    const double INF = 100.0;
    const double scale = INF * 2;

    CCParams<CryptoContextCKKSRNS> params;
    params.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    params.SetMultiplicativeDepth(120);
    params.SetScalingModSize(50);
    params.SetRingDim(262144);
    params.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(FHE);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    vector<EncEdge> encEdges;
    for (auto& edge : edges) {
        EncEdge ee;
        ee.u = edge[0];
        ee.v = edge[1];
        ee.w = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(vector<double>{(double)edge[2]}));
        encEdges.push_back(ee);
    }

    vector<double> initDist(V, INF);
    initDist[src] = 0.0;

    vector<Ciphertext<DCRTPoly>> dist(V);
    for (int i=0; i<V; i++) {
        Plaintext pt = cc->MakeCKKSPackedPlaintext(vector<double>{initDist[i]});
        dist[i] = cc->Encrypt(keys.publicKey, pt);
    }

    for (int i=0; i<V-1; i++) {
        cout << "Iteration " << i + 1 << "/" << V - 1 << endl;

        for (auto& edge : encEdges) {
            Ciphertext<DCRTPoly> candidate = cc->EvalAdd(dist[edge.u], edge.w);
            dist[edge.v] = encMin(cc, dist[edge.v], candidate, scale);
        }
    }

    cout << "\nShortest distances from source " << src << ":\n";
    for (int i=0; i<V; i++) {
        Plaintext pt;
        cc->Decrypt(keys.secretKey, dist[i], &pt);
        pt->SetLength(1);
        double d = pt->GetRealPackedValue()[0];
        int rounded = (int)round(d);
        if (rounded >= (int)INF) {
            cout << "Node " << i << ": INF\n";
        }
        else {
            cout << "Node " << i << ": " << rounded << "\n";
        }
    }

    return 0;
}