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

const auto fuzz::DeviceStateManager::ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
    fuzz::AttributeState ** attributeState = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    VerifyOrDie(attributeState != nullptr);
    return (*attributeState)->Read();
}

template <chip::TLV::TLVType T, AttributeQualityEnum Q>
void fuzz::DeviceStateManager::WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                              const typename ClusterAttribute<T, Q>::underlying_t & aValue)
{
    VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
    auto *& attributeState = ReadValueOrDefault(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    dynamic_cast<ConcreteAttributeState<T, Q> *>(attributeState)->Write(aValue);
}

// TODO: Consider variadic refactoring
void fuzz::DeviceStateManager::Add(NodeId node, DeviceTypeId deviceType)
{
    NodeState state{};
    state.deviceTypeId = deviceType;
    mDeviceState.nodes.emplace(node, state);
}
void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint)
{
    EndpointState state{};
    state.endpointId = endpoint;
    mDeviceState(node)->endpoints.emplace(endpoint, state);
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, int revision = 5)
{
    ClusterState state{};
    state.clusterId       = cluster;
    state.clusterRevision = revision;
    mDeviceState(node, endpoint)->clusters.emplace(cluster, state);
}

template <chip::TLV::TLVType T, AttributeQualityEnum Q>
void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    ConcreteAttributeState<T, Q> state{};
    mDeviceState(node, endpoint, cluster)->attributes.emplace(attribute, state);
}

template <chip::TLV::TLVType T, AttributeQualityEnum Q>
void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                   const typename ClusterAttribute<T, Q>::underlying_t & value)
{
    ConcreteAttributeState<T, Q> state{ value };
    mDeviceState(node, endpoint, cluster)->attributes.emplace(attribute, state);
}
