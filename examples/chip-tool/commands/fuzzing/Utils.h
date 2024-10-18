#pragma once
#include "ForwardDeclarations.h"
#include <numeric>

namespace chip {
namespace fuzzing {

namespace utils {
template <typename T, typename... Args>
struct ExtendedVariant;

template <typename... Args0, typename... Args1>
struct ExtendedVariant<std::variant<Args0...>, Args1...>
{
    using type = std::variant<Args0..., Args1...>;
};

template <typename... Args0, typename... Args1>
struct ExtendedVariant<std::variant<Args0...>, std::variant<Args1...>>
{
    using type = std::variant<Args0..., Args1...>;
};

struct SetKeyHasher
{
    std::size_t operator()(const ConcreteDataAttributePathKey & path) const
    {
        return std::hash<chip::EndpointId>{}(path.mEndpointId) ^ std::hash<chip::ClusterId>{}(path.mClusterId) ^
            std::hash<chip::AttributeId>{}(path.mAttributeId);
    }
};

using DataAttributePathSet = std::unordered_set<chip::app::ConcreteDataAttributePath, SetKeyHasher>;
using FuzzerObservation    = std::tuple<chip::app::ConcreteCommandPath, CHIP_ERROR, DataAttributePathSet>;

struct MapKeyHasher
{
    std::size_t operator()(const OracleRuleMapKey & k) const
    {
        return std::hash<chip::EndpointId>{}(std::get<0>(k)) ^ std::hash<chip::ClusterId>{}(std::get<1>(k)) ^
            std::hash<chip::AttributeId>{}(std::get<2>(k)) ^ std::get<3>(k);
    }

    std::size_t operator()(const ConcreteDataAttributePathKey & path) const
    {
        return std::hash<chip::EndpointId>{}(path.mEndpointId) ^ std::hash<chip::ClusterId>{}(path.mClusterId) ^
            std::hash<chip::AttributeId>{}(path.mAttributeId);
    }

    std::size_t operator()(const FuzzerObservation & k) const
    {
        auto pathSet = std::get<2>(k);
        std::vector<uint64_t> dataAttributePathSetSums(std::get<2>(k).size());
        std::transform(pathSet.begin(), pathSet.end(), dataAttributePathSetSums.begin(), [](auto & path) {
            return static_cast<uint64_t>(path.mEndpointId) + static_cast<uint64_t>(path.mClusterId) +
                static_cast<uint64_t>(path.mAttributeId);
        });

        return std::hash<uint32_t>{}(std::get<0>(k).mEndpointId ^ std::get<0>(k).mClusterId ^ std::get<0>(k).mCommandId) ^
            std::hash<uint32_t>{}(std::get<1>(k).AsInteger()) ^
            std::hash<uint64_t>{}(std::reduce(dataAttributePathSetSums.begin(), dataAttributePathSetSums.end()));
    }

    std::size_t operator()(const CHIP_ERROR & k) const { return std::hash<uint32_t>{}(k.AsInteger()); }
};

struct MapKeyEqualizer
{
    bool operator()(const OracleRuleMapKey & k0, const OracleRuleMapKey & k1) const
    {
        return (std::get<0>(k0) == std::get<0>(k1) && std::get<1>(k0) == std::get<1>(k1) && std::get<2>(k0) == std::get<2>(k1) &&
                std::get<3>(k0) == std::get<3>(k1));
    }

    bool operator()(const FuzzerObservation & k0, const FuzzerObservation & k1) const
    {
        return (std::get<0>(k0) == std::get<0>(k1) && std::get<1>(k0) == std::get<1>(k1) && std::get<2>(k0) == std::get<2>(k1));
    }
};

} // namespace utils

using AnyType                = typename utils::ExtendedVariant<PrimitiveType, ContainerType>::type;
inline AnyType kInvalidValue = std::monostate();

void Indent(size_t indent);
std::string GetElapsedTime(std::chrono::steady_clock::time_point startTime);
void PrintStatusLine(std::chrono::steady_clock::time_point startTime, std::atomic<uint32_t> & currentTest, uint32_t totalTests,
                     CHIP_ERROR lastStatusResponse, const OracleStatus & oracleStatus);
bool IsManufacturerSpecificTestingCluster(ClusterId cluster);

const std::vector<std::pair<TLV::TLVType, uint8_t>> supportedTypes{ { TLV::TLVType::kTLVType_Array, 0 },
                                                                    { TLV::TLVType::kTLVType_Boolean, 0 },
                                                                    { TLV::TLVType::kTLVType_ByteString, 1 },
                                                                    { TLV::TLVType::kTLVType_ByteString, 2 },
                                                                    { TLV::TLVType::kTLVType_ByteString, 4 },
                                                                    { TLV::TLVType::kTLVType_ByteString, 8 },
                                                                    { TLV::TLVType::kTLVType_FloatingPointNumber, 4 },
                                                                    { TLV::TLVType::kTLVType_FloatingPointNumber, 8 },
                                                                    { TLV::TLVType::kTLVType_List, 0 },
                                                                    { TLV::TLVType::kTLVType_Null, 0 },
                                                                    { TLV::TLVType::kTLVType_Structure, 0 },
                                                                    { TLV::TLVType::kTLVType_SignedInteger, 1 },
                                                                    { TLV::TLVType::kTLVType_SignedInteger, 2 },
                                                                    { TLV::TLVType::kTLVType_SignedInteger, 4 },
                                                                    { TLV::TLVType::kTLVType_SignedInteger, 8 },
                                                                    { TLV::TLVType::kTLVType_UnsignedInteger, 1 },
                                                                    { TLV::TLVType::kTLVType_UnsignedInteger, 2 },
                                                                    { TLV::TLVType::kTLVType_UnsignedInteger, 4 },
                                                                    { TLV::TLVType::kTLVType_UnsignedInteger, 8 },
                                                                    { TLV::TLVType::kTLVType_UTF8String, 1 },
                                                                    { TLV::TLVType::kTLVType_UTF8String, 2 },
                                                                    { TLV::TLVType::kTLVType_UTF8String, 4 },
                                                                    { TLV::TLVType::kTLVType_UTF8String, 8 } };
} // namespace fuzzing
} // namespace chip
