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

template <class T>
const T * fuzz::AttributeState::Read()
{
    VerifyOrReturnValue(mValue.HasValue(), nullptr);
    return &(std::any_cast<T>(mValue.Value()));
}

template <class T>
fuzz::AttributeState & fuzz::AttributeState::operator=(const T & aValue)
{
    mValue.SetValue(std::make_any<T>(aValue));
    return *this;
}

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

fuzz::AttributeState * fuzz::DeviceStateManager::GetAttributeState(NodeId node, EndpointId endpoint, ClusterId cluster,
                                                                   AttributeId attribute)
{
    ClusterState * clusterState = mDeviceState(node, endpoint, cluster);
    VerifyOrReturnValue(clusterState != nullptr, nullptr);
    return ReadValueOrNull(clusterState->attributes, attribute);
}

template <class T>
const T * fuzz::DeviceStateManager::ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    AttributeState * attributeState = GetAttributeState(node, endpoint, cluster, attribute);
    VerifyOrReturnValue(attributeState != nullptr, nullptr);
    return attributeState->Read<T>();
}

template <class T>
void fuzz::DeviceStateManager::WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, T aValue)
{
    AttributeState * attributeState = GetAttributeState(node, endpoint, cluster, attribute);
    VerifyOrReturn(attributeState != nullptr,
                   ChipLogError(chipFuzzer, "[DeviceStateManager] failed to write attribute state: %d", attribute));
    *attributeState = aValue;
}

std::unordered_map<chip::ClusterId, fuzz::ClusterState> * fuzz::DeviceStateManager::GetClustersOnEndpoint(NodeId node,
                                                                                                          EndpointId endpoint)
{
    VerifyOrReturnValue(mDeviceState(node, endpoint) != nullptr, nullptr);
    return &mDeviceState(node, endpoint)->clusters;
}

template <typename... Path>
auto * fuzz::DeviceConfiguration::Read(const Path... ids)
{
    return ReadValueOrNull(mConfiguration, ids...);
}

template <typename... Path>
const auto * fuzz::DeviceConfiguration::Read(const Path... ids) const
{
    return ReadValueOrNull(mConfiguration, ids...);
}

template <typename... Path>
auto & fuzz::DeviceConfiguration::Reset(const Path... ids)
{
    return ReadValueOrDefault(mConfiguration, ids...);
}

template <typename V, typename... Path>
bool fuzz::DeviceConfiguration::Write(const Path... ids, const V & aValue)
{
    return WriteValue(mConfiguration, ids..., aValue);
}

// TODO: Consider variadic refactoring
auto & fuzz::DeviceStateManager::ResetState(NodeId node, DeviceTypeId deviceType)
{
    NodeState state{};
    state.deviceTypeId = deviceType;
    mDeviceState.nodes.emplace(node, state);
    return deviceConfig.Reset(node);
}
auto & fuzz::DeviceStateManager::ResetState(NodeId node, EndpointId endpoint)
{
    EndpointState state{};
    state.endpointId = endpoint;
    mDeviceState(node)->endpoints.emplace(endpoint, state);
    return deviceConfig.Reset(node, endpoint);
}
auto & fuzz::DeviceStateManager::ResetState(NodeId node, EndpointId endpoint, ClusterId cluster)
{
    ClusterState state{};
    state.clusterId = cluster;
    mDeviceState(node, endpoint)->clusters.emplace(cluster, state);
    return deviceConfig.Reset(node, endpoint, cluster);
}

template <typename State, typename... Ks>
auto & fuzz::DeviceStateManager::ResetState(const Ks &... ids)
{}
