
#include <any>
#include <app-common/zap-generated/cluster-objects.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <lib/core/TLVData.h>
#include <lib/core/TLVTags.h>
#include <lib/core/TLVTypes.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>
#pragma once

namespace {
template <typename T, typename = void>
struct has_max_len : std::false_type
{
};

// Partial specialization: Case where T has a member variable named value
template <typename T>
struct has_max_len<T, std::void_t<decltype(std::declval<T>().maxLen)>> : std::true_type
{
    using len_b = decltype(std::declval<T>().maxLen);
};

} // namespace

namespace chip {
namespace fuzzing {
namespace TLV {

using TLVType       = chip::TLV::TLVType;
using TLVTag        = chip::TLV::TLVTagControl;
using PrimitiveType = std::variant<bool, char *, float, double, std::nullptr_t, int8_t, int16_t, int32_t, int64_t, uint8_t,
                                   uint16_t, uint32_t, uint64_t, std::string>;
using ContainerType = std::variant<std::unordered_map<std::string, PrimitiveType>, std::vector<PrimitiveType>>;

// Helper trait acting as a switch to the correct type trait, depending on the TLVType and if a size in bytes is specified

// Converts TLV types to primitive types with fixed size (void, std::nullptr_t, bool)
template <TLVType T>
struct TLVToPrimitiveTypeTrait;

// Converts TLV types to container types (std::vector, std::unordered_map)
template <TLVType T>
struct TLVToContainerTypeTrait;

// Converts TLV types to primitive sized types (int, float)
template <TLVType T, uint8_t size_b>
struct TLVToSizedPrimitiveTypeTrait;

// Converts TLV types to primitive types which can have a length (char*, std::string)
template <TLVType T, uint8_t len_b>
struct TLVToPrimitiveTypeTraitWithLength;

template <>
struct TLVToContainerTypeTrait<TLVType::kTLVType_Array>
{
    using type = std::vector<std::variant<PrimitiveType, ContainerType>>;
};

template <>
struct TLVToPrimitiveTypeTrait<TLVType::kTLVType_Boolean>
{
    using type = bool;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_ByteString, 1>
{
    using type     = char *;
    uint8_t maxLen = UINT8_MAX;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_ByteString, 2>
{
    using type      = char *;
    uint16_t maxLen = UINT16_MAX;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_ByteString, 4>
{
    using type      = char *;
    uint32_t maxLen = UINT32_MAX;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_ByteString, 8>
{
    using type      = char *;
    uint64_t maxLen = UINT64_MAX;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_FloatingPointNumber, 4>
{
    using type = float;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_FloatingPointNumber, 8>
{
    using type = double;
};

template <>
struct TLVToContainerTypeTrait<TLVType::kTLVType_List>
{
    using type = std::vector<std::variant<PrimitiveType, ContainerType>>;
};

template <>
struct TLVToPrimitiveTypeTrait<TLVType::kTLVType_NotSpecified>
{
    using type = std::nullptr_t;
};

template <>
struct TLVToPrimitiveTypeTrait<TLVType::kTLVType_Null>
{
    using type = std::nullptr_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_SignedInteger, 1>
{
    using type = int8_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_SignedInteger, 2>
{
    using type = int16_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_SignedInteger, 4>
{
    using type = int32_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_SignedInteger, 8>
{
    using type = int64_t;
};

template <>
struct TLVToContainerTypeTrait<TLVType::kTLVType_Structure>
{
    using type = std::unordered_map<std::string, std::variant<PrimitiveType, ContainerType>>;
};

template <>
struct TLVToPrimitiveTypeTrait<TLVType::kTLVType_UnknownContainer>
{
    using type = void;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_UnsignedInteger, 1>
{
    using type = uint8_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_UnsignedInteger, 2>
{
    using type = uint16_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_UnsignedInteger, 4>
{
    using type = uint32_t;
};

template <>
struct TLVToSizedPrimitiveTypeTrait<TLVType::kTLVType_UnsignedInteger, 8>
{
    using type = uint64_t;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_UTF8String, 1>
{
    using type     = std::string;
    uint8_t maxLen = UINT8_MAX;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_UTF8String, 2>
{
    using type      = std::string;
    uint16_t maxLen = UINT16_MAX;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_UTF8String, 4>
{
    using type      = std::string;
    uint32_t maxLen = UINT32_MAX;
};

template <>
struct TLVToPrimitiveTypeTraitWithLength<TLVType::kTLVType_UTF8String, 8>
{
    using type      = std::string;
    uint64_t maxLen = UINT64_MAX;
};

template <TLVType T, uint8_t bytes = 0>
struct TLVToStandardType;

template <TLVType T>
struct TLVToStandardType<T, 0>
{
    using type = typename std::conditional<(T == TLVType::kTLVType_NotSpecified || T == TLVType::kTLVType_Null ||
                                            T == TLVType::kTLVType_UnknownContainer),
                                           TLVToPrimitiveTypeTrait<T>, TLVToContainerTypeTrait<T>>::type;
};

template <TLVType T, uint8_t bytes>
struct TLVToStandardType
{
    using type =
        typename std::conditional<(T == TLVType::kTLVType_ByteString || T == TLVType::kTLVType_UTF8String),
                                  TLVToPrimitiveTypeTraitWithLength<T, bytes>, TLVToSizedPrimitiveTypeTrait<T, bytes>>::type;
};

// TODO: May tracking the tag value be useful? If yes, disable it when the tag is Anonymous
template <TLVType T, uint8_t bytes = 0, TLVTag tag_t = TLVTag::Anonymous>
struct DecodedTLVElement;

// Encodes a TLV element with C++ std types
template <TLVType T, uint8_t bytes, TLVTag tag_t>
struct DecodedTLVElement
{
    TLVTag tag     = tag_t;
    uint8_t length = bytes;
    typename TLVToStandardType<T, bytes>::type value;
};

template <TLVType T, uint8_t B, TLVTag tag_t,
          typename std::enable_if<has_max_len<DecodedTLVElement<T, B, tag_t>>::value> * = nullptr>
inline size_t GetRemainingLength(DecodedTLVElement<T, B, tag_t> element)
{
    using len_t     = typename has_max_len<DecodedTLVElement<T, B, tag_t>>::len_b;
    using element_t = decltype(element.value);

    len_t maxLen = std::declval<TLVToStandardType<T, B>>().maxLen;
    if (std::is_same_v<std::string, element_t>)
    {
        return maxLen - static_cast<len_t>(element.value.size());
    }
    else
    {
        return maxLen - static_cast<len_t>(strlen(element.value));
    }
}

} // namespace TLV
} // namespace fuzzing
} // namespace chip
