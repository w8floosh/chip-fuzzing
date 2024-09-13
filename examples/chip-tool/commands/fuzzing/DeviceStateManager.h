#pragma once

#include "tlv/TypeMapping.h"
#include <any>
#include <app-common/zap-generated/cluster-objects.h>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum AttributeQualityEnum
{
    kMandatory = 0,
    kNullable  = 1,
    kOptional  = 2,
};

namespace DM = chip::app::DataModel;
namespace {

template <typename Derived, chip::TLV::TLVType T, uint8_t bytes>
struct ClusterAttributeBase
{
    using underlying_t       = typename chip::fuzzing::TLV::DecodedTLVElement<T, bytes>::type;
    chip::TLV::TLVType tlv_t = T;
};

template <chip::TLV::TLVType T, uint8_t bytes = 0, AttributeQualityEnum Q = AttributeQualityEnum::kMandatory>
struct ClusterAttribute;

template <chip::TLV::TLVType T, uint8_t bytes>
struct ClusterAttribute<T, bytes, AttributeQualityEnum::kMandatory>
    : public ClusterAttributeBase<ClusterAttribute<T, bytes, AttributeQualityEnum::kMandatory>, T, bytes>
{
    using underlying_t =
        typename ClusterAttributeBase<ClusterAttribute<T, bytes, AttributeQualityEnum::kMandatory>, T, bytes>::underlying_t;
    AttributeQualityEnum quality = AttributeQualityEnum::kMandatory;
    underlying_t & operator=(const underlying_t & aValue)
    {
        this->value = aValue;
        return this->value;
    };
    underlying_t & operator()() { return this->value; };
    underlying_t value;
};

template <chip::TLV::TLVType T, uint8_t bytes>
struct ClusterAttribute<T, bytes, AttributeQualityEnum::kOptional>
    : public ClusterAttributeBase<ClusterAttribute<T, bytes, AttributeQualityEnum::kOptional>, T, bytes>
{
    using underlying_t =
        typename ClusterAttributeBase<ClusterAttribute<T, bytes, AttributeQualityEnum::kOptional>, T, bytes>::underlying_t;
    AttributeQualityEnum quality = AttributeQualityEnum::kOptional;
    underlying_t & operator=(const underlying_t & aValue)
    {
        this->value.SetValue(aValue);
        return this->value.Value();
    };
    underlying_t & operator()() { return this->value.Value(); };
    chip::Optional<underlying_t> value = chip::NullOptional;
};

template <chip::TLV::TLVType T, uint8_t bytes>
struct ClusterAttribute<T, bytes, AttributeQualityEnum::kNullable>
    : public ClusterAttributeBase<ClusterAttribute<T, bytes, AttributeQualityEnum::kNullable>, T, bytes>
{
    using underlying_t =
        typename ClusterAttributeBase<ClusterAttribute<T, bytes, AttributeQualityEnum::kNullable>, T, bytes>::underlying_t;
    AttributeQualityEnum quality = AttributeQualityEnum::kNullable;
    underlying_t & operator=(const underlying_t & aValue)
    {
        this->value.SetValue(aValue);
        return this->value.Value();
    };
    underlying_t & operator()() { return this->value.Value(); };
    DM::Nullable<underlying_t> value = DM::NullNullable;
};
} // namespace

namespace chip {
namespace fuzzing {

class AttributeState
{
public:
    virtual ~AttributeState()                                                          = 0;
    virtual const ClusterAttribute<chip::TLV::TLVType::kTLVType_NotSpecified> * Read() = 0;
};

template <chip::TLV::TLVType T, uint8_t B = 0, AttributeQualityEnum Q = AttributeQualityEnum::kMandatory>
/**/
class ConcreteAttributeState : public AttributeState
{
    using underlying_t = typename ClusterAttribute<T, B, Q>::underlying_t;

public:
    ConcreteAttributeState() : mValue(ClusterAttribute<T, B, Q>{}) {}
    ConcreteAttributeState(const underlying_t & value) : mValue(ClusterAttribute<T, B, Q>{ value }) {}
    const underlying_t * Read() override { return mValue(); }
    const underlying_t & Write(const underlying_t & value)
    {
        underlying_t oldValue = mValue();
        mValue                = value;
        return oldValue;
    }

private:
    ClusterAttribute<T, B, Q> mValue;
};

struct ClusterState
{
    ClusterId clusterId;
    int clusterRevision;
    std::unordered_map<AttributeId, AttributeState *> attributes;
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

struct DeviceState
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
    template <chip::TLV::TLVType T, AttributeQualityEnum Q>
    using underlying_t = typename ClusterAttribute<T, Q>::underlying_t;

public:
    DeviceStateManager() {};
    ~DeviceStateManager() {};

    const auto ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
    template <chip::TLV::TLVType T, AttributeQualityEnum Q>
    void WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                        const typename ClusterAttribute<T, Q>::underlying_t & aValue);

    auto List() { return mDeviceState.nodes; }
    auto List(NodeId node)
    {
        VerifyOrDie(mDeviceState(node) != nullptr);
        return mDeviceState(node)->endpoints;
    }
    auto List(NodeId node, EndpointId endpoint)
    {
        VerifyOrDie(mDeviceState(node, endpoint) != nullptr);
        return mDeviceState(node, endpoint)->clusters;
    }
    auto List(NodeId node, EndpointId endpoint, ClusterId cluster)
    {
        VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
        return mDeviceState(node, endpoint, cluster)->attributes;
    }

    void Add(NodeId node, DeviceTypeId deviceType);
    void Add(NodeId node, EndpointId endpoint);
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, int revision);
    template <chip::TLV::TLVType T, AttributeQualityEnum Q>
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
    template <chip::TLV::TLVType T, AttributeQualityEnum Q>
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, const underlying_t<T, Q> & value);
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, CommandId command);

private:
    DeviceState mDeviceState;
};

} // namespace fuzzing
} // namespace chip
