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
    ~DeviceStateManager()
    {
        for (auto & nPair : mDeviceState->mNodes)
        {
            for (auto & ePair : nPair.second->mEndpoints)
            {
                for (auto & cPair : ePair.second->mClusters)
                {
                    for (auto & aPair : cPair.second->mAttributes)
                    {
                        free(aPair.second);
                        aPair.second = nullptr;
                    }
                    free(cPair.second);
                    cPair.second = nullptr;
                }
                free(ePair.second);
                ePair.second = nullptr;
            }
            free(nPair.second);
            nPair.second = nullptr;
        }
    }

    template <class T>
    T * GetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, bool returnPreviousValue = false);

private:
    DeviceState * mDeviceState;
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
    T * mValue;
};

struct ClusterState
{
    template <class T>
    AttributeState<T> const * operator[](AttributeId id);
    ClusterId mClusterId;
    std::unordered_map<AttributeId, AttributeState<std::any> *> mAttributes;
};
struct EndpointState
{
    ClusterState const * operator[](ClusterId id);
    EndpointId mEndpointId;
    std::unordered_map<ClusterId, ClusterState *> mClusters;
};

struct NodeState
{
    EndpointState const * operator[](EndpointId id);
    DeviceTypeId mDeviceTypeId;
    std::unordered_map<EndpointId, EndpointState *> mEndpoints;
};

struct DeviceState
{
    NodeState const * operator[](NodeId id);
    FabricId mFabric;
    VendorId mVendor;
    std::unordered_map<NodeId, NodeState *> mNodes;
};

typedef std::any NodeDataRaw;
} // namespace fuzzing
} // namespace chip
