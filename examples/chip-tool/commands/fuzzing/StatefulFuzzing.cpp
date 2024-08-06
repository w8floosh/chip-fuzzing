#include "StatefulFuzzing.h"

namespace fuzz = chip::fuzzing;

namespace {
template <class K, class V>
V * GetElementPointerIfExists(std::unordered_map<K, V *> map, K id)
{
    return map.find(id) != map.end() ? map[id] : nullptr
}
} // namespace

fuzz::stateful::EndpointState * fuzz::stateful::DeviceState::operator[](EndpointId id)
{
    return GetElementPointerIfExists<EndpointId, EndpointState>(mEndpoints, id);
}

fuzz::stateful::ClusterState * fuzz::stateful::EndpointState::operator[](ClusterId id)
{
    return GetElementPointerIfExists<ClusterId, ClusterState>(mClusters, id);
}

template <class T>
fuzz::stateful::AttributeState<T> * fuzz::stateful::ClusterState::operator[](AttributeId id)
{
    return GetElementPointerIfExists<AttributeId, AttributeState<T>>(mAttributes, id);
}

template <class T>
fuzz::stateful::AttributeState<T> & fuzz::stateful::AttributeState<T>::operator=(const T & aValue)
{
    mPrevValue = mCurrValue;
    mCurrValue = aValue;
    return *this;
};

template <class T>
T & fuzz::stateful::AttributeState<T>::operator()(bool current = true)
{
    return current ? mCurrValue : mPrevValue;
}

template <class T>
T * fuzz::stateful::DeviceStateManager::GetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute,
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
CHIP_ERROR fuzz::stateful::DeviceStateManager::SetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value)
{
    using AttributeType = decltype(mDeviceState[endpoint][cluster][attribute]());
    VerifyOrReturnError(std::is_same<AttributeType, T>::value, CHIP_ERROR_INVALID_ARGUMENT);
    mDeviceState[endpoint][cluster][attribute] = value;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::stateful::Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory,
                                Optional<fs::path> stateLogExportDirectory, fuzz::Fuzzer ** fuzzer)
{
    switch (type)
    {
    case AFL_PLUSPLUS:
        *fuzzer = new fuzz::stateful::AFLPlusPlus(seedsDirectory, strategy, stateLogExportDirectory);
        break;
    default:
        return CHIP_ERROR_NOT_IMPLEMENTED;
        break;
    }

    return CHIP_NO_ERROR;
} // namespace chip::fuzzing
