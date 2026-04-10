#include "tfhe_helper.h"
using namespace std;

int main() {
    BinFHEContext cc;
    LWEPrivateKey sk;
    Serial::DeserializeFromFile("cc.bin", cc, SerType::BINARY);
    Serial::DeserializeFromFile("sk.bin", sk, SerType::BINARY);

    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int INF = atoi(getenv("inf"));
    string ENC_DIR = getenv("encOutDir");

    string line;
    while (getline(cin, line)) {
        istringstream iss(line);
        int nodeId;
        iss >> nodeId;

        string nodeDir = ENC_DIR + "/node" + to_string(nodeId);
        HDFSReader distReader(nodeDir + "/dist");
        EncInt encDist = readEncInt(distReader);
        int dist = decryptInt(cc, sk, encDist);
        cout << "Node " << nodeId << " : " << (dist == INF ? "INF" : to_string(dist)) << "\n";
    }
    return 0;
}