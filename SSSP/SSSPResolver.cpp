#include <bits/stdc++.h>
using namespace std;

void printDist(vector<size_t> &dist) {
    for (size_t d: dist) {
        cout << d << " ";
    }
    cout << "\n";
}

size_t find(size_t x, vector<size_t> parent) {
    if (parent[x] != x) {
        parent[x] = find(parent[x], parent);
    }
    return parent[x];
}

void unite(size_t x, size_t y, vector<size_t> parent, vector<size_t> rank) {
    size_t px = find(x, parent);
    size_t py = find(y, parent);
    if (px == py) {
        return;
    }
    if (rank[px] < rank[py]) {
        swap(px, py);
    }
    parent[py] = px;
    if (rank[px] == rank[py]) {
        rank[px]++;
    }
}

vector<size_t> findRoots(size_t k, vector<size_t> S, vector<size_t> W, 
                      size_t V, vector<vector<pair<size_t, size_t>>> &adjList, vector<size_t> &dist) {

    set<size_t> WSet(W.begin(), W.end());
    set<size_t> SSet(S.begin(), S.end());
    
    // Construct forest F (u, v) by filtering edges
    vector<pair<size_t, size_t>> forestEdges;
    for (size_t u=0; u<V; u++) {
        if (!WSet.count(u)) continue;
        for (pair<size_t, size_t> neighbor: adjList[u]) {
            size_t v = neighbor.first;
            size_t w = neighbor.second;
            if (WSet.count(v)) {
                if (dist[v] == dist[u] + w) {
                    forestEdges.push_back({u, v});
                }
            }
        }
    }
    
    // Find connected components using DSU
    vector<size_t> parent, rank;
    parent.resize(V);
    rank.resize(V, 0);
    for (size_t i=0; i<V; i++) {
        parent[i] = i;
    }
    for (pair<size_t, size_t> p: forestEdges) {
        size_t u = p.first;
        size_t v = p.second;
        unite(u, v, parent, rank);
    }
    
    // Count vertices in each tree and find roots
    unordered_map<size_t, vector<size_t>> components; // DSU root -> list of vertices
    unordered_map<size_t, size_t> rootVertex; // Component DSU root -> tree root vertex
    for (size_t v: W) {
        size_t root = find(v, parent);
        components[root].push_back(v);
    }
    
    // For each component, determine the root vertex
    for (pair<size_t, size_t> p: forestEdges) {
        size_t u = p.first;
        size_t v = p.second;
        size_t root = find(u, parent);
        rootVertex[root] = u; // Assume u is the parent (candidate root)
    }
    
    vector<size_t> P;
    for (pair<size_t, vector<size_t>> p: components) {
        if (p.second.size() >= k) {
            if (rootVertex.count(p.first) && SSet.count(rootVertex[p.first])) {
                P.push_back(rootVertex[p.first]);
            }
        }
    }
    return P;
}

pair<vector<size_t>, vector<size_t>> findPivots(size_t k, size_t B, vector<size_t> S, 
                                                size_t V, vector<vector<pair<size_t, size_t>>> &adjList, vector<size_t> &dist) {
    vector<size_t> W = S;
    vector<vector<size_t>> Wi(k+1);
    Wi[0] = S;
    for (size_t i=1; i<=k; i++) {
        Wi[i].clear();
        for (size_t u: Wi[i-1]) {
            for (pair<size_t, size_t> neighbor: adjList[u]) {
                size_t v = neighbor.first;
                size_t w = neighbor.second;
                if (dist[u] + w <= dist[v]) {
                    dist[v] = dist[u] + w;
                    if (dist[u] + w < B) {
                        Wi[i].push_back(v);
                    }
                }
            }
        }
        for (size_t v: Wi[i]) {
            W.push_back(v);
        }
        if (W.size() > k * S.size()) {
            return {S, W};
        }
    }
    return {findRoots(k, S, W, V, adjList, dist), W};
}

pair<size_t, vector<size_t>> bmsspBaseCase(size_t k, size_t B, vector<size_t> S, vector<vector<pair<size_t, size_t>>> &adjList, vector<size_t> &dist) {
    vector<size_t> U0 = S;
    priority_queue<pair<size_t, size_t>, vector<pair<size_t, size_t>>, greater<pair<size_t, size_t>>> heap; // dist, vertex
    heap.push({dist[U0[0]], U0[0]});
    while (!heap.empty() && U0.size() < k+1) {
        pair<size_t, size_t> minVert = heap.top();
        heap.pop();
        size_t u = minVert.second;
        size_t du = minVert.first;
        U0.push_back(u);
        for (pair<size_t, size_t> neighbor: adjList[u]) {
            size_t v = neighbor.first;
            size_t w = neighbor.second;
            if (du + w <= dist[v] && du + w < B) {
                dist[v] = du + w;
                bool findV = false;
                priority_queue<pair<size_t, size_t>, vector<pair<size_t, size_t>>, greater<pair<size_t, size_t>>> heap2;
                while (heap.size() > 0 && !findV) {
                    if (heap.top().second == v) {
                        heap2.push({dist[v], v});
                        findV = true;
                    }
                    else {
                        heap2.push(heap.top());
                    }
                    heap.pop();
                }
                heap = heap2;
            }
        }
    }
    if (U0.size() <= k) {
        return {B, U0};
    }
    else {
        size_t B2 = -1;
        vector<size_t> U;
        for (size_t v: U0) {
            B2 = max(B2, dist[v]);
        }
        for (size_t v: U0) {
            if (dist[v] < B2) {
                U.push_back(v);
            }
        }
        return {B2, U};
    }
}

void insert(set<pair<size_t, size_t>> &D, size_t key, size_t value) {
    auto it = D.begin();
    while (it != D.end() && it->second != key) {
        it++;
    }
    if (it != D.end()) {
        if (it->first <= value) {
            return;
        }
        D.erase(it);
    }
    D.insert({value, key});
}

void batchPrepend(set<pair<size_t, size_t>> &D, vector<pair<size_t, size_t>> pairs, size_t B) {
    size_t minValue = D.empty() ? B : D.begin()->first;
    for (pair<size_t, size_t> p: pairs) {
        size_t key = p.first;
        size_t value = p.second;
        if (value >= minValue) {
            continue;
        }
        auto it = D.begin();
        while (it != D.end() && it->second != key) {
            it++;
        }
        if (it != D.end()) {
            if (it->first <= value) {
                continue;
            }
            D.erase(it);
        }
        D.insert({value, key});
    }
}

pair<size_t, vector<size_t>> pull(set<pair<size_t, size_t>> &D, size_t M, size_t B) {
    vector<size_t> keys;
    vector<pair<size_t, size_t>> toRemove;
    size_t x = B;

    for (auto it = D.begin(); it != D.end() && keys.size() < M; it++) {
        size_t vertex = it->second;
        if (find(keys.begin(), keys.end(), vertex) == keys.end()) {
            keys.push_back(vertex);
            toRemove.push_back(*it);
        }
    }

    if (keys.size() < D.size()) {
        auto it = D.begin();
        advance(it, toRemove.size());
        if (it != D.end()) {
            x = it->first;
        }
    }

    for (pair<size_t, size_t> p: toRemove) {
        D.erase(p);
    }

    return {x, keys};
}

pair<size_t, vector<size_t>> bmssp(size_t l, size_t k, size_t t, size_t B, vector<size_t> S, size_t V, vector<vector<pair<size_t, size_t>>> &adjList, vector<size_t> &dist) {
    if (l == 0) {
        return bmsspBaseCase(k, B, S, adjList, dist);
    }
    pair<vector<size_t>, vector<size_t>> p = findPivots(k, B, S, V, adjList, dist);
    vector<size_t> P = p.first;
    vector<size_t> W = p.second;
    set<pair<size_t, size_t>> D;
    vector<size_t> Bi;
    vector<vector<size_t>> Si;
    vector<size_t> newBi;
    vector<vector<size_t>> Ui;
    vector<size_t> U;
    size_t i = 0;
    if (P.empty()) {
        newBi.push_back(B);
    }
    else {
        size_t newB = -1;
        for (size_t x: P) {
            insert(D, x, dist[x]);
            newB = min(newB, dist[x]);
        }
        newBi.push_back(newB);
    }
    Bi.push_back(-1);
    Si.push_back({});
    Ui.push_back({});
    while (U.size() < k * pow(2, l * t) && !D.empty()) {
        i++;
        pair<size_t, vector<size_t>> temp = pull(D, pow(2, (l-1) * t), B);
        Bi.push_back(temp.first);
        Si.push_back(temp.second);
        pair<size_t, vector<size_t>> temp2 = bmssp(l-1, k, t, Bi[i], Si[i], V, adjList, dist);
        newBi.push_back(temp2.first);
        Ui.push_back(temp2.second);
        for (size_t x: Ui[i]) {
            U.push_back(x);
        }
        vector<pair<size_t, size_t>> K;
        for (size_t u: Ui[i]) {
            for (pair<size_t, size_t> neighbor: adjList[u]) {
                size_t v = neighbor.first;
                size_t w = neighbor.second;
                if (dist[u] + w <= dist[v]) {
                    dist[v] = dist[u] + w;
                    if (dist[u] + w >= Bi[i] && dist[u] + w < B) {
                        insert(D, v, dist[u] + w);
                    }
                    else if (dist[u] + w >= newBi[i] && dist[u] + w < Bi[i]) {
                        K.push_back({v, dist[u] + w});
                    }
                }
            }
        }
        vector<pair<size_t, size_t>> newK = K;
        for (size_t x: Si[i]) {
            if (dist[x] >= newBi[i] && dist[x] < Bi[i]) {
                K.push_back({x, dist[x]});
            }
        }
        batchPrepend(D, newK, B);
    }
    for (size_t newB: newBi) {
        B = min(newB, B);
    }
    for (size_t x: W) {
        if (dist[x] >= newBi[i] && dist[x] < Bi[i]) {
            U.push_back(x);
        }
    }
    return {B, U};
}

vector<size_t> dijkstra(size_t V, vector<vector<pair<size_t, size_t>>> &adjList, vector<size_t> &dist, size_t src) {
    priority_queue<pair<size_t, size_t>, vector<pair<size_t, size_t>>, greater<pair<size_t, size_t>>> heap; // dist, vertex
    heap.push({0, src});
    dist[src] = 0;
    while (!heap.empty()) {
        size_t u = heap.top().second;
        heap.pop();
        for (pair<size_t, size_t> neighbor: adjList[u]) {
            size_t v = neighbor.first;
            size_t w = neighbor.second;
            if (dist[u] + w < dist[v]) {
                dist[v] = dist[u] + w;
                heap.push({dist[v], v});
            }
        }
    }
    return dist;
}

// Generate graphs in form of u, v, weight
vector<vector<size_t>> generateGraph() {
    return {
        {0, 1, 4}, 
        {0, 2, 8}, 
        {1, 4, 6}, 
        {2, 3, 2}, 
        {3, 4, 10}
    };
}

// Construct the Adjacency List from the Graph
vector<vector<pair<size_t, size_t>>> constructAdjList(size_t V, vector<vector<size_t>> &graph) {
    vector<vector<pair<size_t, size_t>>> adjList(V);
    for (vector<size_t> edge: graph) {
        size_t u = edge[0];
        size_t v = edge[1];
        size_t w = edge[2];
        adjList[u].push_back({v, w});
        adjList[v].push_back({u, w});
    }
    return adjList;
}

int main() {
    size_t V = 150000000;
    size_t src = 0;
    vector<vector<size_t>> graph = generateGraph();
    vector<vector<pair<size_t, size_t>>> adjList = constructAdjList(5, graph);
    vector<size_t> dist(V, INT_MAX);
    dijkstra(V, adjList, dist, src);
    //printDist(dist);

    size_t k = floor(pow(log2(V), 1.0 / 3.0));
    size_t t = floor(pow(log2(V), 2.0 / 3.0));
    cout << k << " " << t << "\n";
    vector<size_t> S;
    S.push_back(src);
    vector<size_t> dist2(V, INT_MAX);
    bmssp(ceil(log(V) / t), k, t, INT_MAX, S, V, adjList, dist2);
    // printDist(dist2);
    return 0;
}