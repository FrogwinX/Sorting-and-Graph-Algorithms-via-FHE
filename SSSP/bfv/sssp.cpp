#include "bfv_helper.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
#include <vector>

using namespace std;
using namespace lbcrypto;
using namespace chrono;

int main() {
    int V = 5;
    int src = 0;
    string filename = "small_weight_graph_" + to_string(V);

    ifstream inFile("../../graphs/small_weight_graph/data/" + filename);
    if (!inFile.is_open()) {
        cerr << "Error opening graph file.\n";
        return 1;
    }

    vector<vector<int>> edges;
    int u, v, w;
    while (inFile >> u >> v >> w) {
        edges.push_back({u, v, w});
    }
    inFile.close();

    CryptoContext<DCRTPoly> cc = makeBFVContext(30);
    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    Ciphertext<DCRTPoly> cZero = encryptBit(cc, keys.publicKey, 0);
    Ciphertext<DCRTPoly> cOne = encryptBit(cc, keys.publicKey, 1);

    ofstream logFile("../small_weight_graph/log/" + filename + "_log");
    if (!logFile.is_open()) {
        cerr << "Error opening log file.\n";
        return 1;
    }
    logFile << "Log for BFV Bellman-Ford on " << filename << "\n" << flush;

    auto encStart = high_resolution_clock::now();
    vector<EncEdge> encEdges;
    encEdges.reserve(edges.size());
    for (auto& edge : edges) {
        EncEdge ee;
        ee.u = edge[0];
        ee.v = edge[1];
        ee.w = encryptInt(cc, keys.publicKey, edge[2]);
        encEdges.push_back(ee);
    }

    vector<EncInt> dist(V);
    for (int i=0; i<V; i++) {
        dist[i] = encryptInt(cc, keys.publicKey, i == src ? 0 : INF_VAL);
    }
    auto encEnd = high_resolution_clock::now();
    logFile << "Encryption time: " << (encEnd - encStart).count() / 1e9 << " sec\n" << flush;

    auto totalStart = high_resolution_clock::now();
    for (int i=0; i<V-1; i++) {
        auto start = high_resolution_clock::now();
        for (auto& edge : encEdges) {
            EncInt newDist = encAdd(cc, cZero, dist[edge.u], edge.w);
            dist[edge.v] = encMin(cc, cZero, cOne, dist[edge.v], newDist);
        }
        auto end = high_resolution_clock::now();
        logFile << "Iteration " << i + 1 << ": " << (end - start).count() / 1e9 << " sec\n" << flush;

        for (int i=0; i<V; i++) {
            int d = decryptInt(cc, keys.secretKey, dist[i]);
            cout << "Node " << i << ": " << d << "\n";
        }
    }
    auto totalEnd = high_resolution_clock::now();
    logFile << "Total time: " << (totalEnd - totalStart).count() / 1e9 << " sec\n" << flush;

    ofstream outFile("../small_weight_graph/output/" + filename + "_output");
    if (!outFile.is_open()) {
        cerr << "Error opening output file.\n";
        return 1;
    }
    outFile << "Shortest distances from source " << src << ":\n";

    auto decStart = high_resolution_clock::now();
    for (int i=0; i<V; i++) {
        int d = decryptInt(cc, keys.secretKey, dist[i]);
        if (d >= INF_VAL) {
            outFile << "Node " << i << ": INF\n";
        }
        else {
            outFile << "Node " << i << ": " << d << "\n";
        }
    }
    auto decEnd = high_resolution_clock::now();
    logFile << "Decryption time: " << (decEnd - decStart).count() / 1e9 << " sec\n" << flush;

    logFile.close();
    outFile.close();
    return 0;
}