#include "DeviceStateManager.h"

namespace fuzz = chip::fuzzing;

namespace {
template <class K, class V>
V const * GetElementPtrIfExists(const std::unordered_map<K, V *> & map, K id)
{
    auto found = map.find(id) const;
    return found != map.end() ? map[id] : nullptr
}
} // namespace

fuzz::NodeState const * fuzz::DeviceState::operator[](NodeId id)
{
    return GetElementPtrIfExists<NodeId, NodeState>(mNodes, id);
}

fuzz::EndpointState const * fuzz::NodeState::operator[](EndpointId id)
{
    return GetElementPtrIfExists<EndpointId, EndpointState>(mEndpoints, id);
}

fuzz::ClusterState const * fuzz::EndpointState::operator[](ClusterId id)
{
    return GetElementPtrIfExists<ClusterId, ClusterState>(mClusters, id);
}

template <class T>
fuzz::AttributeState<T> const * fuzz::ClusterState::operator[](AttributeId id)
{
    return GetElementPtrIfExists<AttributeId, AttributeState<T>>(mAttributes, id);
}

template <class T>
fuzz::AttributeState<T> & fuzz::AttributeState<T>::operator=(const T & aValue)
{
    *mValue = *aValue;
    return *this;
};

template <class T>
T & fuzz::AttributeState<T>::operator()()
{
    return mValue;
}

template <class T>
T * fuzz::DeviceStateManager::GetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                           bool returnPreviousValue = false)
{
    if (mDeviceState[endpoint] == nullptr)
        return nullptr;
    if (mDeviceState[endpoint][cluster] == nullptr)
        return nullptr;
    if (mDeviceState[endpoint][cluster][attribute] == nullptr)
        return nullptr;

    using AttributeType = decltype(mDeviceState[endpoint][cluster][attribute]());
    VerifyOrReturnError(std::is_same<AttributeType, T *>::value, CHIP_ERROR_INTERNAL);

    return reinterpret_cast<T *>(mDeviceState[endpoint][cluster][attribute](!returnPreviousValue));
}

template <class T>
CHIP_ERROR fuzz::DeviceStateManager::SetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value)
{
    using AttributeType = decltype(mDeviceState[endpoint][cluster][attribute]());
    VerifyOrReturnError(std::is_same<AttributeType, T>::value, CHIP_ERROR_INVALID_ARGUMENT);
    mDeviceState[endpoint][cluster][attribute] = value;
    return CHIP_NO_ERROR;
}
