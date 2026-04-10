#include "tfhe_helper.h"
using namespace std;

int main() {
    BinFHEContext cc;
    LWEPrivateKey sk;
    Serial::DeserializeFromFile("cc.bin", cc, SerType::BINARY);
    Serial::DeserializeFromFile("sk.bin", sk, SerType::BINARY);

    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int SOURCE_NODE = atoi(getenv("sourceNode"));
    int INF = atoi(getenv("inf"));
    string ENC_DIR = getenv("encOutDir");

    int oldFrom = -1;
    vector<pair<int, int>> adjList;
    
    auto flush = [&](int nodeId) {
        cout << nodeId << "\n";
        string nodeDir = ENC_DIR + "/node" + to_string(nodeId);

        EncInt encDist = encryptInt(cc, sk, (nodeId == SOURCE_NODE) ? 0 : INF);
        HDFSWriter distWriter(nodeDir + "/dist");
        writeEncInt(distWriter, encDist);
        distWriter.flush();

        HDFSWriter edgeWriter(nodeDir + "/edge");
        if (adjList.empty()) {
            return;
        }
        for (auto& edge : adjList) {
            EncEdge e { 
                nodeId, 
                edge.first, 
                encryptInt(cc, sk, edge.second) 
            };
            writeEncEdge(edgeWriter, e);
        }
        edgeWriter.flush();
        adjList.clear();
    };

    string line;
    while (getline(cin, line)) {
        istringstream iss(line);
        int from, to, cost;
        iss >> from >> to >> cost;

        if (from != oldFrom && oldFrom != -1) {
            flush(oldFrom);
        }
        oldFrom = from;

        if (to != -1) {
            adjList.push_back({to, cost});
        }
    }
    flush(oldFrom);

    return 0;
}