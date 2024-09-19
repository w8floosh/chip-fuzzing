#include "DeviceStateManager.h"

namespace fuzz = chip::fuzzing;

namespace {
template <typename K, typename V>
V * ReadValueOrNull(std::unordered_map<K, V> & map, K id)
{
    auto found = map.find(id);
    VerifyOrReturnValue(found != map.end(), nullptr);
    return &(found->second);
}

// Variadic variant of ReadValueOrNull
template <typename Map, typename K>
auto * ReadValueOrNull(Map & map, const K & id)
{
    auto found      = map.find(id);
    using ValueType = decltype(found->second);
    VerifyOrReturnValue(found != map.end(), static_cast<ValueType *>(nullptr));
    return &(found->second);
}

template <typename Map, typename K, typename... Path>
auto * ReadValueOrNull(Map & map, const K & id, const Path &... ids)
{
    auto found      = map.find(id);
    using ValueType = decltype(found->second);
    VerifyOrReturnValue(found != map.end(), static_cast<ValueType *>(nullptr));
    return ReadValueOrNull(found->second, ids...);
}
// This sets a default value to a key in a map if it doesn't already exist, then returns it
template <typename Map, typename K>
auto & ReadValueOrDefault(Map & map, const K & id)
{
    return map[id];
}
template <typename Map, typename K, typename... Path>
auto & ReadValueOrDefault(Map & map, const K & id, const Path &... ids)
{
    return ReadValueOrDefault(map[id], ids...);
}

// This sets a default value to a key in a map if it doesn't already exist, then returns it
template <typename Map, typename K, typename V>
bool WriteValue(Map & map, const K & id, const V & aValue)
{
    return map.emplace(id, aValue)->second;
}
template <typename Map, typename K, typename V, typename... Path>
bool WriteValue(Map & map, const K & id, const Path &... ids, const V & aValue)
{
    return WriteValue(map[id], ids...);
}

} // namespace

fuzz::NodeState * fuzz::DeviceState::operator()(NodeId id)
{
    return ReadValueOrNull(nodes, id);
}

fuzz::EndpointState * fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint)
{
    VerifyOrReturnValue((*this)(node) != nullptr, nullptr);
    return ReadValueOrNull((*this)(node)->endpoints, endpoint);
}

fuzz::ClusterState * fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint, ClusterId cluster)
{
    VerifyOrReturnValue((*this)(node, endpoint) != nullptr, nullptr);
    return ReadValueOrNull((*this)(node, endpoint)->clusters, cluster);
}

const auto fuzz::DeviceStateManager::ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                                   bool current)
{
    VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
    AttributeState * attributeState = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    VerifyOrDie(attributeState != nullptr);
    return current ? attributeState->ReadCurrent() : attributeState->ReadLast();
}

void fuzz::DeviceStateManager::WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                              const AnyType & aValue)
{
    VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
    AttributeState & attributeState = ReadValueOrDefault(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    attributeState.Write(aValue);
}

// TODO: Consider variadic refactoring
void fuzz::DeviceStateManager::Add(NodeId node)
{
    NodeState state{};
    mDeviceState.nodes.emplace(node, state);
}
void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, DeviceTypeId deviceType)
{
    EndpointState state{};
    state.endpointId   = endpoint;
    state.deviceTypeId = deviceType;
    mDeviceState(node)->endpoints.emplace(endpoint, state);
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, int revision = 5)
{
    ClusterState state{};
    state.clusterId       = cluster;
    state.clusterRevision = revision;
    mDeviceState(node, endpoint)->clusters.emplace(cluster, state);
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    AttributeState state{};
    mDeviceState(node, endpoint, cluster)->attributes.emplace(attribute, state);
}
