#include <vector>
#include <queue>
#include <limits>
#include <algorithm>

using namespace std;

// Struct to represent a vertex and its distance, used in priority queue
struct VertexDistance {
    size_t vertex;
    double distance;

    explicit VertexDistance(size_t v, double d) : vertex(v), distance(d) {}

    // Comparison for min-heap (smaller distance first, vertex ID as tiebreaker)
    bool operator<(const VertexDistance& other) const {
        if (distance != other.distance) {
            return distance > other.distance; // Smaller distance has higher priority
        }
        return vertex > other.vertex; // Smaller vertex ID for equal distances
    }
};

// Data structure to manage vertices and distances efficiently
class AdaptiveDataStructure {
private:
    priority_queue<VertexDistance> data; // Min-heap for storing vertex-distance pairs
    size_t capacity; // Maximum number of vertices to pull at once
    double bound; // Upper bound for valid distances

public:
    AdaptiveDataStructure(size_t cap, double b) : capacity(cap), bound(b) {}

    // Insert a vertex with its distance if within bound
    void insert(size_t vertex, double distance) {
        if (distance < bound && distance != INFINITY) {
            data.push(VertexDistance(vertex, distance));
        }
    }

    // Insert multiple vertex-distance pairs (equivalent to multiple inserts)
    void batch_prepend(const vector<pair<size_t, double>>& items) {
        for (const auto& [vertex, distance] : items) {
            insert(vertex, distance);
        }
    }

    // Pull up to capacity vertices with smallest distances
    pair<double, vector<size_t>> pull() {
        vector<size_t> result;
        double min_remaining = bound;

        while (result.size() < capacity && !data.empty()) {
            auto vd = data.top();
            data.pop();
            result.push_back(vd.vertex);

            if (!data.empty()) {
                min_remaining = min(min_remaining, data.top().distance);
            }
        }

        return {min_remaining, result};
    }

    // Check if the data structure is empty
    bool is_empty() const {
        return data.empty();
    }
};