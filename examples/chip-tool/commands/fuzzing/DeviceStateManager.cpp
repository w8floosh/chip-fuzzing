#include "DeviceStateManager.h"

namespace fuzz = chip::fuzzing;

namespace {
template <class K, class V>
V & GetElementIfExists(const std::unordered_map<K, V> & map, K id)
{
    auto found = map.find(id);
    return found != map.end() ? map[id] : nullptr
}
} // namespace

fuzz::NodeState & fuzz::DeviceState::operator[](NodeId id)
{
    return GetElementIfExists<NodeId, NodeState>(mNodes, id);
}

fuzz::EndpointState & fuzz::NodeState::operator[](EndpointId id)
{
    return GetElementIfExists<EndpointId, EndpointState>(mEndpoints, id);
}

fuzz::ClusterState & fuzz::EndpointState::operator[](ClusterId id)
{
    return GetElementIfExists<ClusterId, ClusterState>(mClusters, id);
}

template <class T>
fuzz::AttributeState<T> & fuzz::ClusterState::operator[](AttributeId id)
{
    return GetElementIfExists<AttributeId, AttributeState<T>>(mAttributes, id);
}

template <class T>
fuzz::AttributeState<T> & fuzz::AttributeState<T>::operator=(const T & aValue)
{
    mValue.SetValue(aValue);
    return *this;
};

template <class T>
T & fuzz::AttributeState<T>::operator()()
{
    if (mValue.HasValue())
        return mValue;
    return nullptr;
}

template <class T>
T * fuzz::DeviceStateManager::GetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                           bool returnPreviousValue = false)
{
    static_assert(std::is_same<AttributeType, T>::value, "wrong attribute type");

    VerifyOrReturnValue(!mDeviceState[endpoint], nullptr);
    VerifyOrReturnValue(!mDeviceState[endpoint][cluster], nullptr);
    VerifyOrReturnValue(!mDeviceState[endpoint][cluster][attribute], nullptr);

    auto value          = mDeviceState[endpoint][cluster][attribute]();
    using AttributeType = decltype(value);
    VerifyOrReturnError(value != nullptr, CHIP_ERROR_NOT_FOUND);

    if (mDeviceState[endpoint][cluster][attribute](!returnPreviousValue) == nullptr)
        return nullptr;
    return reinterpret_cast<T *>(mDeviceState[endpoint][cluster][attribute]());
}

template <class T>
CHIP_ERROR fuzz::DeviceStateManager::SetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value)
{
    using AttributeType = decltype(mDeviceState[endpoint][cluster][attribute]());
    VerifyOrReturnError(std::is_same<AttributeType, T>::value, CHIP_ERROR_INVALID_ARGUMENT);
    mDeviceState[endpoint][cluster][attribute] = value;
    return CHIP_NO_ERROR;
}
