#include "tfhe_helper.h"
using namespace std;

int main() {
    BinFHEContext cc;
    LWECiphertext cZero;
    Serial::DeserializeFromFile("cc.bin", cc, SerType::BINARY);
    Serial::DeserializeFromFile("czero.bin", cZero, SerType::BINARY);

    RingGSWACCKey refreshKey;
    LWESwitchingKey switchKey;
    Serial::DeserializeFromFile("btkey.bin", refreshKey, SerType::BINARY);
    Serial::DeserializeFromFile("kskey.bin", switchKey, SerType::BINARY);
    cc.BTKeyLoad({refreshKey, switchKey});
    
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    string ENC_DIR = getenv("encOutDir");

    string line;
    while (getline(cin, line)) {
        vector<EncEdge> edges;
        istringstream iss(line);
        int nodeId;
        iss >> nodeId;

        string nodeDir = ENC_DIR + "/node" + to_string(nodeId);

        HDFSReader distReader(nodeDir + "/dist");
        EncInt dist = readEncInt(distReader);

        HDFSReader edgeReader(nodeDir + "/edge");
        while (!edgeReader.eof()) {
            EncEdge edge = readEncEdge(edgeReader);
            cout << edge.v << " " << nodeId << "\n";
            edges.push_back(edge);
        }

        for (auto& edge : edges) {
            string newDistPath = ENC_DIR + "/node" + to_string(edge.v) + "/newDist/from" + to_string(nodeId);
            HDFSWriter newDistWriter(newDistPath);
            EncInt newDist = encAdd(cc, cZero, dist, edge.w);
            writeEncInt(newDistWriter, newDist);
            newDistWriter.flush();
        }
    }
    return 0;
}