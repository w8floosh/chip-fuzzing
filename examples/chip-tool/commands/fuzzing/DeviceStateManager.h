#pragma once

#include <any>
#include <app-common/zap-generated/cluster-objects.h>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

/**
 * Namespace containing some useful traits for working with multilevel unordered maps.
 * This is used to build a multilevel unordered map with a variadic number of key types.
 * The multilevel_unordered_map_t alias template is provided for convenience.
 */

template <typename... Types>
struct multilevel_unordered_map;

// Recursive case: Builds an unordered_map with the first key type and recurses with the rest.
template <typename KeyType, typename... Rest>
struct multilevel_unordered_map<KeyType, Rest...>
{
    using type = std::unordered_map<KeyType, typename multilevel_unordered_map<Rest...>::type>;
};

// Specialization for the case when there are only two types left: a single KeyType and the ValueType.
template <typename KeyType, typename ValueType>
struct multilevel_unordered_map<KeyType, ValueType>
{
    using type = std::unordered_map<KeyType, ValueType>;
};

// Convenience alias template
template <typename... Types>
using multilevel_unordered_map_t = typename multilevel_unordered_map<Types...>::type;

} // namespace

namespace chip {
namespace fuzzing {

class AttributeState
{
public:
    AttributeId id;
    std::string name;

    AttributeState(AttributeId aId) : id(aId), name(""), mValue(Optional<std::any>::Missing()) {};
    AttributeState(AttributeId aId, std::string aName) : id(aId), name(aName), mValue(Optional<std::any>::Missing()) {};
    template <class T>
    AttributeState(AttributeId aId, std::string aName, T aValue) :
        id(aId), name(aName), mValue(Optional<std::any>::Value(std::make_any<T>(aValue))){};

    template <class T>
    const T * Read();

    template <class T>
    AttributeState & operator=(const T & aValue);

private:
    // TODO: Attribute types are not known at compile time, so std::any is used. Other ideas?
    Optional<std::any> mValue;
};
struct ClusterState
{
    ClusterId clusterId;
    std::unordered_map<AttributeId, AttributeState> attributes;
};
struct EndpointState
{
    EndpointId endpointId;
    std::unordered_map<ClusterId, ClusterState> clusters;
};

struct NodeState
{
    DeviceTypeId deviceTypeId;
    std::unordered_map<EndpointId, EndpointState> endpoints;
};

class DeviceState
{
public:
    FabricId fabric;
    VendorId vendor;
    std::unordered_map<NodeId, NodeState> nodes;

    NodeState * operator()(NodeId id);
    EndpointState * operator()(NodeId node, EndpointId endpoint);
    ClusterState * operator()(NodeId node, EndpointId endpoint, ClusterId cluster);
};

/**
 * @class DeviceConfiguration
 * @brief Keeps a trace of the device configuration tree using resource IDs only.
 *
 * The DeviceStateManager class is responsible for managing the state of devices. It provides methods for
 * retrieving and setting attributes of a device, as well as accessing the clusters associated with a device's
 * endpoint. The class also contains a DeviceState object that represents the current state of the device.
 */
class DeviceConfiguration
{
public:
    DeviceConfiguration() {};
    ~DeviceConfiguration() {};

    /**
     * @fn operator()
     * @brief Retrieves the configuration of a device, endpoint, or cluster by recursively scanning the configuration.
     * Returns nullptr if the requested resource is not yet configured.
     */
    template <typename... Ks>
    auto * Read(const Ks... ids);
    template <typename... Ks>
    const auto * Read(const Ks... ids) const;
    template <typename... Ks>
    auto & Reset(const Ks... ids);
    template <typename V, typename... Ks>
    bool Write(const Ks... ids, const V & aValue);

private:
    multilevel_unordered_map_t<NodeId, EndpointId, ClusterId, std::unordered_set<AttributeId>> mConfiguration;
};

/**
 * @class DeviceStateManager
 * @brief Manages the state of devices and provides methods for accessing and modifying device attributes.
 *
 * The DeviceStateManager class is responsible for managing the state of devices. It provides methods for
 * retrieving and setting attributes of a device, as well as accessing the clusters associated with a device's
 * endpoint. The class also contains a DeviceState object that represents the current state of the device.
 *
 * TODO: Extend this to manage state of groups of devices.
 */
class DeviceStateManager
{
public:
    DeviceStateManager() {};
    ~DeviceStateManager() {};

    DeviceConfiguration deviceConfig;

    template <class T>
    const T * ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
    template <class T>
    void WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value);
    std::unordered_map<ClusterId, ClusterState> * GetClustersOnEndpoint(NodeId node, EndpointId endpoint);

    auto & ResetState(NodeId node, DeviceTypeId deviceType);
    auto & ResetState(NodeId node, EndpointId endpoint);
    auto & ResetState(NodeId node, EndpointId endpoint, ClusterId cluster);

private:
    DeviceState mDeviceState;
    AttributeState * GetAttributeState(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
};

} // namespace fuzzing
} // namespace chip
