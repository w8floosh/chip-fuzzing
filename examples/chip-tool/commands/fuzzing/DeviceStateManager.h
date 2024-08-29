#include <any>
#include <app-common/zap-generated/cluster-objects.h>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <unordered_map>

namespace chip {
namespace fuzzing {
class DeviceStateManager
{
public:
    DeviceStateManager() {};
    ~DeviceStateManager() {}

    template <class T>
    T * GetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, bool returnPreviousValue = false);

private:
    DeviceState mDeviceState;
    template <class T>
    CHIP_ERROR SetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value);
};

template <class T>
class AttributeState
{
public:
    T & operator()();
    AttributeState<T> & operator=(const T & aValue);
    AttributeId mAttributeId;

private:
    Optional<T> mValue;
};

struct ClusterState
{
    template <class T>
    AttributeState<T> & operator[](AttributeId id);
    ClusterId mClusterId;
    std::unordered_map<AttributeId, AttributeState<std::any>> mAttributes;
};
struct EndpointState
{
    ClusterState & operator[](ClusterId id);
    EndpointId mEndpointId;
    std::unordered_map<ClusterId, ClusterState> mClusters;
};

struct NodeState
{
    EndpointState & operator[](EndpointId id);
    DeviceTypeId mDeviceTypeId;
    std::unordered_map<EndpointId, EndpointState> mEndpoints;
};

struct DeviceState
{
    NodeState & operator[](NodeId id);
    FabricId mFabric;
    VendorId mVendor;
    std::unordered_map<NodeId, NodeState> mNodes;
};

typedef std::any NodeDataRaw;
} // namespace fuzzing
} // namespace chip
