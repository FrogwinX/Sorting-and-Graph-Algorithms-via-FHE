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
    
    int oldNodeId = -1;
    EncInt minDist;
    
    auto update = [&](int nodeId) {
        HDFSWriter distWriter(ENC_DIR + "/node" + to_string(nodeId) + "/dist");
        writeEncInt(distWriter, minDist);
        distWriter.flush();
    };
    
    string line;
    while (getline(cin, line)) {
        istringstream iss(line);
        int nodeId, in;
        iss >> nodeId >> in;

        if (nodeId != oldNodeId) {
            if (oldNodeId != -1) {
                update(oldNodeId);
            }
            HDFSReader oldDistReader(ENC_DIR + "/node" + to_string(nodeId) + "/dist");
            minDist = readEncInt(oldDistReader);
        }
        oldNodeId = nodeId;

        HDFSReader distReader(ENC_DIR + "/node" + to_string(nodeId) + "/newDist/from" + to_string(in));
        EncInt dist = readEncInt(distReader);
        minDist = encMin(cc, cZero, minDist, dist);
    }
    update(oldNodeId);

    return 0;
}