#pragma once
#include "ForwardDeclarations.h"
#include <iostream>

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
} // namespace utils
using ContainerType = std::vector<std::shared_ptr<TLV::DecodedTLVElement>>;
using AnyType       = typename utils::ExtendedVariant<PrimitiveType, ContainerType>::type;

inline AnyType kInvalidValue = std::monostate();

inline void Indent(size_t indent)
{
    for (size_t i = 0; i < indent; i++)
    {
        std::cout << " ";
    }
}

inline bool IsManufacturerSpecificTestingCluster(ClusterId cluster)
{
    /**
     * Standard clusters are in range 0x0000_0000 - 0x0007_FFFF.
     * Manufacturer-specific clusters are in range 0x0001_XXXX - 0xFFF4_YYYY, where XXXX >= FC00 and YYYY <= FFFE.
     * Valid mnufacturer-specific clusters IDs ranging from 0xFFF1_0000 to 0xFFF4_FFFE are reserved to testing.
     */
    uint32_t manufacturerCode        = cluster & 0xFFFF0000;
    uint32_t manufacturerProductCode = cluster & 0x0000FFFE;
    return manufacturerCode >= 0xFFF10000 && manufacturerCode <= 0xFFF4FFFE && manufacturerProductCode >= 0xFC00;
}

const std::vector<std::pair<TLVType, uint8_t>> supportedTypes{ { TLVType::kTLVType_Array, 0 },
                                                               { TLVType::kTLVType_Boolean, 0 },
                                                               { TLVType::kTLVType_ByteString, 1 },
                                                               { TLVType::kTLVType_ByteString, 2 },
                                                               { TLVType::kTLVType_ByteString, 4 },
                                                               { TLVType::kTLVType_ByteString, 8 },
                                                               { TLVType::kTLVType_FloatingPointNumber, 4 },
                                                               { TLVType::kTLVType_FloatingPointNumber, 8 },
                                                               { TLVType::kTLVType_List, 0 },
                                                               { TLVType::kTLVType_Null, 0 },
                                                               { TLVType::kTLVType_Structure, 0 },
                                                               { TLVType::kTLVType_SignedInteger, 1 },
                                                               { TLVType::kTLVType_SignedInteger, 2 },
                                                               { TLVType::kTLVType_SignedInteger, 4 },
                                                               { TLVType::kTLVType_SignedInteger, 8 },
                                                               { TLVType::kTLVType_UnsignedInteger, 1 },
                                                               { TLVType::kTLVType_UnsignedInteger, 2 },
                                                               { TLVType::kTLVType_UnsignedInteger, 4 },
                                                               { TLVType::kTLVType_UnsignedInteger, 8 },
                                                               { TLVType::kTLVType_UTF8String, 1 },
                                                               { TLVType::kTLVType_UTF8String, 2 },
                                                               { TLVType::kTLVType_UTF8String, 4 },
                                                               { TLVType::kTLVType_UTF8String, 8 } };
} // namespace fuzzing
} // namespace chip
