#include <bits/stdc++.h>
using namespace std;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    string SOURCE_NODE = getenv("sourceNode");
    
    string line;
    while (getline(cin, line)) {
        istringstream iss(line);
        string u, v, w;
        iss >> u >> v >> w;
        cout << line << "\n";
        cout << v << " " << "-1" << " " << "-1" << "\n";
    }
    cout << SOURCE_NODE << " " << "-1" << " " << "-1" << "\n";
    return 0;
}