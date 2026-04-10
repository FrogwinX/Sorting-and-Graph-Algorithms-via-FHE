#include "fhe_helper.h"
#include <iostream>
#include <chrono>

using namespace std;

int main() {
    int V = 25;
    int src = 0;
    string filename = "sparse_graph_" + to_string(V);

    ifstream inFile("../../graphs/sparse_graph/data/" + filename);
    if (!inFile.is_open()) {
        cerr << "Error opening file.\n";
        return 1;
    }

    vector<vector<int>> edges;
    int u, v, w;
    while (inFile >> u >> v >> w) {
        edges.push_back({u, v, w});
    }
    inFile.close();

    // BinFHE context setup
    BinFHEContext cc;
    LWEPrivateKey sk;
    LWECiphertext cZero;
    cc.GenerateBinFHEContext(STD128_LMKCDEY, LMKCDEY);
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    cZero = cc.Encrypt(sk, 0, FRESH, 4);

    ofstream logFile("../sparse_graph/log/" + filename + "_log");
    if (!logFile.is_open()) {
        cerr << "Error opening file.\n";
        return 1;
    }
    logFile << "Log for running Bellman-Ford on " << filename << "\n" << flush;

    // Encrypt edge weights
    auto encStart = chrono::high_resolution_clock::now();
    vector<EncEdge> encEdges;
    for (auto& edge : edges) {
        EncEdge ee;
        ee.u = edge[0];
        ee.v = edge[1];
        ee.w = encryptInt(cc, sk, edge[2]);
        encEdges.push_back(ee);
    }

    // Encrypt initial distance array
    vector<EncInt> dist(V);
    for (int i=0; i<V; i++) {
        dist[i] = encryptInt(cc, sk, i == src ? 0 : INF_VAL);
    }
    auto encEnd = chrono::high_resolution_clock::now();
    logFile << "Encryption time: " << (encEnd - encStart).count() / 1e9 << " sec\n" << flush;

    // Bellman-Ford relaxation
    auto totalStart = chrono::high_resolution_clock::now();
    for (int i=0; i<V-1; i++) {
        auto start = chrono::high_resolution_clock::now();
        for (auto& edge : encEdges) {
            EncInt newDist = encAdd(cc, cZero, dist[edge.u], edge.w);
            dist[edge.v] = encMin(cc, cZero, dist[edge.v], newDist);
        }
        auto end = chrono::high_resolution_clock::now();
        logFile << "Iteration " << i+1 << ": " << (end - start).count() / 1e9 << " sec\n" << flush;
    }
    auto totalEnd = chrono::high_resolution_clock::now();
    logFile << "Total time: " << (totalEnd - totalStart).count() / 1e9 << " sec\n" << flush;

    // Decrypt and display results
    ofstream outFile("../sparse_graph/output/" + filename + "_output");
    outFile << "Shortest distances from source " << src << ":\n";
    if (!outFile.is_open()) {
        cerr << "Error opening file.\n";
        return 1;
    }

    auto decStart = chrono::high_resolution_clock::now();
    for (int i=0; i<V; i++) {
        int d = decryptInt(cc, sk, dist[i]);
        if (d >= INF_VAL) {
            outFile << "Node " << i << ": INF\n";
        }
        else {
            outFile << "Node " << i << ": " << d << "\n";
        }
    }
    auto decEnd = chrono::high_resolution_clock::now();
    logFile << "Decryption time: " << (decEnd - decStart).count() / 1e9 << " sec\n" << flush;
    logFile.close();
    outFile.close();

    return 0;
}