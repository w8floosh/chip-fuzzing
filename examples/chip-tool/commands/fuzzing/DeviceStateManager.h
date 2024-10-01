#pragma once
#include "AttributeFactory.h"
#include "ForwardDeclarations.h"
#include "Utils.h"
#include <unordered_map>

namespace DM = chip::app::DataModel;
namespace chip {
namespace fuzzing {
class AttributeState
{
public:
    AttributeState() {};
    // Copy constructor
    AttributeState(const AttributeState & other)
    {
        if (other.mValue)
        {
            mValue = std::make_unique<AttributeWrapper>(*other.mValue);
        }
        if (other.mOldValue)
        {
            mOldValue = std::make_unique<AttributeWrapper>(*other.mOldValue);
        }
    }
    // Move constructor
    AttributeState(AttributeState && other) noexcept : mValue(std::move(other.mValue)), mOldValue(std::move(other.mOldValue)) {}
    // Copy assignment operator
    AttributeState & operator=(const AttributeState & other)
    {
        if (this != &other)
        {
            mValue.reset();
            mOldValue.reset();
            if (other.mValue)
            {
                mValue = std::make_unique<AttributeWrapper>(*other.mValue);
            }
            if (other.mOldValue)
            {
                mOldValue = std::make_unique<AttributeWrapper>(*other.mOldValue);
            }
        }
        return *this;
    }
    // Move assignment operator
    AttributeState & operator=(AttributeState && other) noexcept
    {
        if (this != &other)
        {
            mValue    = std::move(other.mValue);
            mOldValue = std::move(other.mOldValue);
        }
        return *this;
    }
    AttributeState(TLVType aType, uint8_t bytes, AttributeQualityEnum aQuality)
    {
        mValue = AttributeFactory::Create(aType, bytes, aQuality);
    }
    AttributeState(TLVType aType, uint8_t bytes, AttributeQualityEnum aQuality, AnyType && value)
    {
        mValue = AttributeFactory::Create(aType, std::move(value), bytes, aQuality);
    }
    const AnyType & ReadCurrent()
    {
        VerifyOrReturnValue(mReadable && (mValue != nullptr), kInvalidValue);
        return mValue->Read();
    }
    const AnyType & ReadLast()
    {
        VerifyOrReturnValue(mReadable && (mOldValue != nullptr), kInvalidValue);
        return mOldValue->Read();
    }
    CHIP_ERROR Write(AnyType && value)
    {
        VerifyOrReturnError(mValue != nullptr, CHIP_ERROR_INCORRECT_STATE);
        // Move the current value to the older pointer AFTER the new value write has been successful (for state consistency)
        auto old = std::make_shared<AttributeWrapper>(*mValue);
        ReturnErrorOnFailure(mValue->Write(std::move(value)));
        mOldValue = std::move(old);
        mReadable = true;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR LazyInitialize(TLVType aType, uint8_t bytes, AttributeQualityEnum aQuality, AnyType && value)
    {
        mValue = std::move(AttributeFactory::Create(aType, std::move(value), bytes, aQuality));
        VerifyOrReturnError(mValue != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
        return CHIP_NO_ERROR;
    }

    // If the attribute is unreadable, any read access to it is denied
    void ToggleBlockReads() { mReadable = !mReadable; }
    bool IsReadable() { return mReadable; }

private:
    // Some attributes may be blocked or uninitialized, e.g. when reading them, the device returns a 0x01 status code (FAILURE)
    bool mReadable                              = true;
    std::shared_ptr<AttributeWrapper> mValue    = nullptr;
    std::shared_ptr<AttributeWrapper> mOldValue = nullptr;
};

struct DeviceTypeStruct
{
    DeviceTypeId id;
    uint16_t revision;
};

struct ClusterState
{
    ClusterId clusterId;
    uint16_t clusterRevision;
    std::unordered_map<AttributeId, AttributeState> attributes;
};

struct EndpointState
{
    EndpointId endpointId;
    std::vector<DeviceTypeStruct> deviceTypes;
    std::unordered_map<ClusterId, ClusterState> clusters;
};

struct NodeState
{
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
 * The DeviceStateManager class is responsible for tracking and managing the state of devices. It provides methods for
 * retrieving and setting attributes of a device, as well as accessing the clusters associated with a device's
 * endpoint.
 *
 * NOTE: Changes to the device state through this class are not reflected in the actual remote device state.
 *
 * TODO: Extend this to manage state of groups of devices.
 */
class DeviceStateManager
{
public:
    DeviceStateManager(fs::path dumpDir) : mDumpDirectory(dumpDir)
    {
        if (!fs::exists(mDumpDirectory))
        {
            VerifyOrDie(fs::create_directory(mDumpDirectory));
        }
    };
    ~DeviceStateManager() {};

    const AnyType & ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, bool current = true);
    AttributeState & GetAttributeState(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);
    void WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute, AnyType && aValue);

    auto List() { return &mDeviceState.nodes; }
    auto List(NodeId node)
    {
        VerifyOrDie(mDeviceState(node) != nullptr);
        return &mDeviceState(node)->endpoints;
    }
    auto List(NodeId node, EndpointId endpoint)
    {
        VerifyOrDie(mDeviceState(node, endpoint) != nullptr);
        return &mDeviceState(node, endpoint)->clusters;
    }
    auto List(NodeId node, EndpointId endpoint, ClusterId cluster)
    {
        VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
        return &mDeviceState(node, endpoint, cluster)->attributes;
    }

    // The Add methods are used to add new nodes, endpoints, clusters, and attributes to the device state.
    void Add(NodeId node);
    void Add(NodeId node, EndpointId endpoint);
    void Add(NodeId node, EndpointId endpoint, DeviceTypeStruct deviceType);
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, uint16_t revision = 5U);
    void Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute);

    /**
     * @brief Dumps the current device state to a YAML file.
     */
    CHIP_ERROR Dump(std::vector<std::string> commandHistory = std::vector<std::string>{});

    /**
     * @brief Loads a device state snapshot from a YAML file.
     */
    CHIP_ERROR Load(fs::path src);

private:
    DeviceState mDeviceState;
    fs::path mDumpDirectory;
};

} // namespace fuzzing
} // namespace chip
