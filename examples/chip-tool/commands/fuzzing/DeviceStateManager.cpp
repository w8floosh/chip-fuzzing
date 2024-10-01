#include "DeviceStateManager.h"
#include "Visitors.h"
#include "tlv/DecodedTLVElement.h"
#include <fstream>
// This header has exception handling code that is not compatible with -fno-exceptions (see BUILD.gn)
#include <yaml-cpp/yaml.h>

namespace fuzz = chip::fuzzing;

namespace {
template <typename K, typename V>
V * ReadValueOrNull(std::unordered_map<K, V> & map, K id)
{
    auto found = map.find(id);
    VerifyOrReturnValue(found != map.end(), nullptr);
    return &(found->second);
}

// Variadic variant of ReadValueOrNull
template <typename Map, typename K>
auto * ReadValueOrNull(Map & map, const K & id)
{
    auto found      = map.find(id);
    using ValueType = decltype(found->second);
    VerifyOrReturnValue(found != map.end(), static_cast<ValueType *>(nullptr));
    return &(found->second);
}

template <typename Map, typename K, typename... Path>
auto * ReadValueOrNull(Map & map, const K & id, const Path &... ids)
{
    auto found      = map.find(id);
    using ValueType = decltype(found->second);
    VerifyOrReturnValue(found != map.end(), static_cast<ValueType *>(nullptr));
    return ReadValueOrNull(found->second, ids...);
}
// This sets a default value to a key in a map if it doesn't already exist, then returns it
template <typename Map, typename K>
auto & ReadValueOrDefault(Map & map, const K & id)
{
    return map[id];
}
template <typename Map, typename K, typename... Path>
auto & ReadValueOrDefault(Map & map, const K & id, const Path &... ids)
{
    return ReadValueOrDefault(map[id], ids...);
}

// This sets a default value to a key in a map if it doesn't already exist, then returns it
template <typename Map, typename K, typename V>
bool WriteValue(Map & map, const K & id, const V & aValue)
{
    return map.emplace(id, aValue)->second;
}
template <typename Map, typename K, typename V, typename... Path>
bool WriteValue(Map & map, const K & id, const Path &... ids, const V & aValue)
{
    return WriteValue(map[id], ids...);
}

CHIP_ERROR LoadValue(const YAML::detail::iterator_value & attribute, fuzz::AnyType & value)
{
    if (attribute["type"].as<std::string>() == "bool")
    {
        value = attribute["value"].as<bool>();
    }
    else if (attribute["type"].as<std::string>() == "byte string")
    {
        char * byteString = new char[attribute["value"].as<std::string>().size() + 1];
        strncpy(byteString, attribute["value"].as<std::string>().c_str(), attribute["value"].as<std::string>().size() + 1);
        value = byteString;
    }
    else if (attribute["type"].as<std::string>() == "unsigned integer 1")
    {
        value = attribute["value"].as<uint8_t>();
    }
    else if (attribute["type"].as<std::string>() == "unsigned integer 2")
    {
        value = attribute["value"].as<uint16_t>();
    }
    else if (attribute["type"].as<std::string>() == "unsigned integer 4")
    {
        value = attribute["value"].as<uint32_t>();
    }
    else if (attribute["type"].as<std::string>() == "unsigned integer 8")
    {
        value = attribute["value"].as<uint64_t>();
    }
    else if (attribute["type"].as<std::string>() == "signed integer 1")
    {
        value = attribute["value"].as<int8_t>();
    }
    else if (attribute["type"].as<std::string>() == "signed integer 2")
    {
        value = attribute["value"].as<int16_t>();
    }
    else if (attribute["type"].as<std::string>() == "signed integer 4")
    {
        value = attribute["value"].as<int32_t>();
    }
    else if (attribute["type"].as<std::string>() == "signed integer 8")
    {
        value = attribute["value"].as<int64_t>();
    }
    else if (attribute["type"].as<std::string>() == "float")
    {
        value = attribute["value"].as<float>();
    }
    else if (attribute["type"].as<std::string>() == "double")
    {
        value = attribute["value"].as<double>();
    }
    else if (attribute["type"].as<std::string>() == "utf8 string")
    {
        value = attribute["value"].as<std::string>();
    }
    else if (attribute["type"].as<std::string>() == "container")
    {
        // TODO: Manage conversion
        fuzz::ContainerType container{};
        for (const auto & element : attribute["value"])
        {
            auto nestedElement = std::make_shared<fuzz::TLV::DecodedTLVElement>();
            ReturnErrorOnFailure(LoadValue(element, nestedElement->content));
            container.push_back(std::move(nestedElement));
        }
        value = container;
    }
    else
    {
        return CHIP_ERROR_INTERNAL;
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DumpContainer(const fuzz::ContainerType & container, YAML::Emitter & emitter)
{

    emitter << YAML::Key << "value" << YAML::BeginSeq;
    for (const auto & element : container)
    {
        std::string attributeType = fuzz::Visitors::AttributeTypeAsString(element->content);
        emitter << YAML::BeginMap;
        emitter << YAML::Key << "type" << YAML::Value << attributeType;
        if (attributeType == "container")
        {
            VerifyOrReturnError(std::holds_alternative<fuzz::ContainerType>(element->content), CHIP_ERROR_INTERNAL);
            ReturnErrorOnFailure(DumpContainer(std::get<fuzz::ContainerType>(element->content), emitter));
        }
        else
            emitter << YAML::Key << "value" << YAML::Value << fuzz::Visitors::AttributeValueAsString(element->content);

        emitter << YAML::EndMap;
    }
    emitter << YAML::EndSeq;
    return CHIP_NO_ERROR;
}

} // namespace

fuzz::NodeState * fuzz::DeviceState::operator()(NodeId id)
{
    return ReadValueOrNull(nodes, id);
}

fuzz::EndpointState * fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint)
{
    VerifyOrReturnValue((*this)(node) != nullptr, nullptr);
    return ReadValueOrNull((*this)(node)->endpoints, endpoint);
}

fuzz::ClusterState * fuzz::DeviceState::operator()(NodeId node, EndpointId endpoint, ClusterId cluster)
{
    VerifyOrReturnValue((*this)(node, endpoint) != nullptr, nullptr);
    return ReadValueOrNull((*this)(node, endpoint)->clusters, cluster);
}

const fuzz::AnyType & fuzz::DeviceStateManager::ReadAttribute(NodeId node, EndpointId endpoint, ClusterId cluster,
                                                              AttributeId attribute, bool current)
{
    VerifyOrReturnValue(mDeviceState(node, endpoint, cluster) != nullptr, kInvalidValue);
    AttributeState * attributeState = ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    VerifyOrReturnValue(attributeState != nullptr, kInvalidValue);
    return current ? attributeState->ReadCurrent() : attributeState->ReadLast();
}
fuzz::AttributeState & fuzz::DeviceStateManager::GetAttributeState(NodeId node, EndpointId endpoint, ClusterId cluster,
                                                                   AttributeId attribute)
{
    return ReadValueOrDefault(mDeviceState(node, endpoint, cluster)->attributes, attribute);
}

void fuzz::DeviceStateManager::WriteAttribute(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute,
                                              AnyType && aValue)
{
    VerifyOrDie(mDeviceState(node, endpoint, cluster) != nullptr);
    AttributeState & attributeState = ReadValueOrDefault(mDeviceState(node, endpoint, cluster)->attributes, attribute);
    attributeState.Write(std::move(aValue));
}

// TODO: Consider variadic refactoring
void fuzz::DeviceStateManager::Add(NodeId node)
{
    VerifyOrReturn(mDeviceState(node) == nullptr);
    NodeState state{};
    auto pair = mDeviceState.nodes.emplace(node, state);
    VerifyOrDieWithMsg(pair.second, chipFuzzer, "pacchitosoru");
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId);
    VerifyOrReturn((mDeviceState(node) != nullptr) && (mDeviceState(node, endpoint) == nullptr));
    EndpointState state{};
    state.endpointId = endpoint;
    VerifyOrDie(mDeviceState(node)->endpoints.emplace(endpoint, state).second);
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, DeviceTypeStruct deviceType)
{
    VerifyOrReturn((endpoint != kInvalidEndpointId) && (deviceType.id != kInvalidClusterId));
    VerifyOrReturn(mDeviceState(node) != nullptr);
    if (mDeviceState(node, endpoint) != nullptr)
    {
        mDeviceState(node, endpoint)->deviceTypes.push_back(deviceType);
    }
    else
    {
        EndpointState state{};
        state.endpointId  = endpoint;
        state.deviceTypes = std::vector<DeviceTypeStruct>();
        VerifyOrDie(mDeviceState(node)->endpoints.emplace(endpoint, state).second);
    }
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, uint16_t revision)
{
    VerifyOrReturn((endpoint != kInvalidEndpointId) && (cluster != kInvalidClusterId));
    VerifyOrReturn((mDeviceState(node, endpoint) != nullptr) && (mDeviceState(node, endpoint, cluster) == nullptr));
    ClusterState state{};
    state.clusterId       = cluster;
    state.clusterRevision = revision;
    VerifyOrDie(mDeviceState(node, endpoint)->clusters.emplace(cluster, state).second);
}

void fuzz::DeviceStateManager::Add(NodeId node, EndpointId endpoint, ClusterId cluster, AttributeId attribute)
{
    VerifyOrReturn((endpoint != kInvalidEndpointId) && (cluster != kInvalidClusterId) && (attribute != kInvalidAttributeId));
    VerifyOrReturn((mDeviceState(node, endpoint, cluster) != nullptr) &&
                   (ReadValueOrNull(mDeviceState(node, endpoint, cluster)->attributes, attribute) == nullptr));

    AttributeState state{};
    VerifyOrDie(mDeviceState(node, endpoint, cluster)->attributes.emplace(attribute, state).second);
}

/**
 * Creates a YAML file and dumps the device state in it.
 * Dumping the device state is a costly operation, as the function traverses and copies the whole device state inside a std::map to
 * dump the keys in ascending order.
 */
CHIP_ERROR fuzz::DeviceStateManager::Dump(std::vector<std::string> commandHistory)
{
    // TODO: Add dumping for events and events history
    auto now    = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    YAML::Emitter emitter;

    emitter << YAML::BeginMap;
    emitter << YAML::Key << "timestamp" << YAML::Value << std::to_string(now_ms);
    emitter << YAML::Key << "nodes" << YAML::Value << YAML::BeginMap;
    const auto nodes = *List();
    for (auto & [nodeId, nodeState] : std::map<NodeId, NodeState>(nodes.begin(), nodes.end()))
    {
        emitter << YAML::Key << nodeId << YAML::Value << YAML::BeginMap;
        emitter << YAML::Key << "endpoints" << YAML::Value << YAML::BeginMap;
        const auto endpoints = *List(nodeId);
        for (auto & [endpointId, endpointState] : std::map<EndpointId, EndpointState>(endpoints.begin(), endpoints.end()))
        {
            emitter << YAML::Key << endpointId << YAML::Value << YAML::BeginMap;
            emitter << YAML::Key << "deviceTypes" << YAML::Value << YAML::BeginSeq;

            std::set<DeviceTypeId> deviceTypeIds;
            for (auto & deviceType : endpointState.deviceTypes)
            {
                if (deviceTypeIds.find(deviceType.id) == deviceTypeIds.end())
                {
                    deviceTypeIds.emplace(deviceType.id);
                    emitter << YAML::BeginMap << YAML::Key << "id" << YAML::Value << deviceType.id;
                    emitter << YAML::Key << "revision" << YAML::Value << deviceType.revision << YAML::EndMap;
                }
            }
            emitter << YAML::EndSeq;

            emitter << YAML::Key << "clusters" << YAML::Value << YAML::BeginMap;
            const auto clusters = *List(nodeId, endpointId);

            for (auto & [clusterId, clusterState] : std::map<ClusterId, ClusterState>(clusters.begin(), clusters.end()))
            {
                emitter << YAML::Key << clusterId << YAML::Value << YAML::BeginMap;
                emitter << YAML::Key << "revision" << YAML::Value << clusterState.clusterRevision;
                emitter << YAML::Key << "attributes" << YAML::Value << YAML::BeginMap;
                const auto attributes = *List(nodeId, endpointId, clusterId);
                for (auto & [attributeId, attributeState] :
                     std::map<AttributeId, AttributeState>(attributes.begin(), attributes.end()))
                {
                    if (!attributeState.IsReadable())
                    {
                        emitter << YAML::Key << attributeId << YAML::Value << "unreadable";
                        continue;
                    }
                    const AnyType & attributeValue = attributeState.ReadCurrent();
                    emitter << YAML::Key << attributeId << YAML::Value << YAML::BeginMap;
                    std::string attributeType = Visitors::AttributeTypeAsString(attributeValue);
                    emitter << YAML::Key << "type" << YAML::Value << attributeType;
                    if (attributeType == "container")
                    {
                        VerifyOrReturnError(std::holds_alternative<ContainerType>(attributeValue), CHIP_ERROR_INTERNAL);
                        ReturnErrorOnFailure(DumpContainer(std::get<ContainerType>(attributeValue), emitter));
                    }
                    else
                    {
                        emitter << YAML::Key << "value" << YAML::Value << Visitors::AttributeValueAsString(attributeValue);
                    }
                    // TODO: We should manage nullable/optional attributes (we may add a nullable: true/false or optional:
                    // TODO: true/false field)
                    emitter << YAML::EndMap;
                }

                emitter << YAML::EndMap;
                emitter << YAML::EndMap;
            }

            emitter << YAML::EndMap;
            emitter << YAML::EndMap;
        }

        emitter << YAML::EndMap;
        emitter << YAML::EndMap;
    }

    emitter << YAML::EndMap;

    if (commandHistory.size() != 0)
    {
        emitter << YAML::Key << "history" << YAML::Value << YAML::BeginSeq;
        for (const auto & command : commandHistory)
        {
            emitter << YAML::Value << command;
        }
        emitter << YAML::EndSeq;
    }

    emitter << YAML::EndMap;

    std::string fileName(std::to_string(now_ms));
    std::ofstream file(mDumpDirectory / fileName);
    file << emitter.c_str();
    file.close();

    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::DeviceStateManager::Load(fs::path src)
{
    VerifyOrReturnError(fs::exists(src), CHIP_ERROR_OPEN_FAILED);
    YAML::Node root = YAML::LoadFile(src.string());
    VerifyOrReturnError(root.IsMap() && root["nodes"], CHIP_ERROR_INVALID_ARGUMENT);
    for (const auto & node : root["nodes"])
    {
        VerifyOrReturnError(node.IsMap() && node["endpoints"], CHIP_ERROR_INVALID_ARGUMENT);
        Add(node.first.as<NodeId>());
        for (const auto & endpoint : node["endpoints"])
        {
            VerifyOrReturnError(endpoint.IsMap() && endpoint["clusters"] && endpoint["deviceType"], CHIP_ERROR_INVALID_ARGUMENT);
            Add(node.first.as<NodeId>(), endpoint.first.as<EndpointId>(), endpoint["deviceType"].as<DeviceTypeId>());
            for (const auto & cluster : endpoint["clusters"])
            {
                VerifyOrReturnError(cluster.IsMap() && cluster["attributes"] && cluster["revision"], CHIP_ERROR_INVALID_ARGUMENT);
                Add(node.first.as<NodeId>(), endpoint.first.as<EndpointId>(), cluster.first.as<ClusterId>(),
                    cluster["revision"].as<uint16_t>());
                for (const auto & attribute : cluster["attributes"])
                {
                    VerifyOrReturnError(attribute.IsMap() && attribute["type"] && attribute["value"], CHIP_ERROR_INVALID_ARGUMENT);
                    AnyType value;
                    ReturnErrorOnFailure(LoadValue(attribute, value));
                    WriteAttribute(node.first.as<NodeId>(), endpoint.first.as<EndpointId>(), cluster.first.as<ClusterId>(),
                                   attribute.first.as<AttributeId>(), std::move(value));
                }
            }
        }
    }
    return CHIP_NO_ERROR;
}
