#include "DeviceStateManager.h"

namespace fuzz = chip::fuzzing;

namespace {
template <class K, class V>
V & ValueOrNull(const std::unordered_map<K, V> & map, K id)
{
    auto found = map.find(id);
    return found != map.end() ? map[id] : nullptr
}
} // namespace

fuzz::NodeState & fuzz::DeviceState::operator()(NodeId id)
{
    return ValueOrNull(nodes, id);
}

fuzz::EndpointState & fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint)
{
    VerifyOrReturnValue((*this)(node) != nullptr, nullptr);
    return ValueOrNull((*this)(node).endpoints, endpoint);
}

fuzz::ClusterState & fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint, ClusterId cluster)
{
    VerifyOrReturnValue((*this)(node, endpoint) != nullptr, nullptr);
    return ValueOrNull((*this)(node, endpoint).clusters, cluster);
}

template <class T>
fuzz::AttributeState<T> & fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    VerifyOrReturnValue((*this)(node, endpoint, cluster) != nullptr, nullptr);
    return ValueOrNull((*this)(node, endpoint, cluster).attributes, attribute)
}

template <class T>
T * fuzz::DeviceStateManager::GetAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    VerifyOrReturnValue(!mDeviceState(node, endpoint, cluster, attribute), nullptr);
    auto value = mDeviceState(node, endpoint, cluster, attribute)();
    VerifyOrReturnValue(value != nullptr, nullptr);

    using AttributeType = decltype(value);
    static_assert(std::is_same<AttributeType, T>::value, "wrong attribute type");

    return reinterpret_cast<T *>(value);
}

template <class T>
CHIP_ERROR fuzz::DeviceStateManager::SetAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                                  T value)
{
    VerifyOrReturnValue(!mDeviceState(node, endpoint, cluster, attribute), nullptr);
    auto value = mDeviceState(node, endpoint, cluster, attribute)();
    VerifyOrReturnValue(value != nullptr, nullptr);

    using AttributeType = decltype(value);
    static_assert(std::is_same<AttributeType, T>::value, "wrong attribute type");
    mDeviceState(node, endpoint, cluster, attribute) = value;
    return CHIP_NO_ERROR;
}

std::unordered_map<chip::ClusterId, fuzz::ClusterState> * fuzz::DeviceStateManager::GetEndpointClusters(NodeId node,
                                                                                                        EndpointId endpoint)
{
    VerifyOrReturnValue(!mDeviceState(node, endpoint), nullptr);
    return &mDeviceState(node, endpoint).clusters;
}
