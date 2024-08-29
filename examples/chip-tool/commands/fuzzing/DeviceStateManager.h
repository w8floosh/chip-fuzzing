#include <any>
#include <app-common/zap-generated/cluster-objects.h>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <unordered_map>

namespace chip {
namespace fuzzing {
/**
 * @class DeviceStateManager
 * @brief Manages the state of devices and provides methods for accessing and modifying device attributes.
 *
 * The DeviceStateManager class is responsible for managing the state of devices. It provides methods for
 * retrieving and setting attributes of a device, as well as accessing the clusters associated with a device's
 * endpoint. The class also contains a DeviceState object that represents the current state of the device.
 */
class DeviceStateManager

{
public:
    DeviceStateManager() {};
    ~DeviceStateManager() {};

    template <class T>
    T * GetAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
    template <class T>
    CHIP_ERROR SetAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value);
    std::unordered_map<ClusterId, ClusterState> * GetEndpointClusters(NodeId node, EndpointId endpoint);

private:
    DeviceState mDeviceState;
};

template <class T>
class AttributeState
{
public:
    const AttributeId id;
    const std::string name;

    T & operator()() { return mValue.ValueOr(nullptr); }
    AttributeState<T> & operator=(const T & aValue)
    {
        mValue.SetValue(aValue);
        return *this;
    }

private:
    Optional<T> mValue;
};
struct ClusterState
{
    const ClusterId clusterId;
    std::unordered_map<AttributeId, AttributeState<std::any>> attributes;
};
struct EndpointState
{
    const EndpointId endpointId;
    std::unordered_map<ClusterId, ClusterState> clusters;
};

struct NodeState
{
    const DeviceTypeId deviceTypeId;
    std::unordered_map<EndpointId, EndpointState> endpoints;
};

class DeviceState
{
public:
    // DeviceState(FabricId aFabric, VendorId aVendor) : fabric(aFabric), vendor(aVendor) {};
    FabricId fabric;
    VendorId vendor;
    std::unordered_map<NodeId, NodeState> nodes;

    NodeState & operator()(NodeId id);
    EndpointState & operator()(NodeId node, EndpointId endpoint);
    ClusterState & operator()(NodeId node, EndpointId endpoint, ClusterId cluster);
    template <class T>
    AttributeState<T> & operator()(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
};

typedef std::any NodeDataRaw;
} // namespace fuzzing
} // namespace chip
