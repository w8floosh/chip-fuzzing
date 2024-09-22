#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"
#include "Visitors.h"

namespace DM = chip::app::DataModel;
namespace chip {
namespace fuzzing {

enum AttributeQualityEnum
{
    kNullable,
    kOptional,
    kMandatory,
};

struct AttributeWrapper
{
    AttributeWrapper(const AttributeWrapper & other)                 = default;
    AttributeWrapper(AttributeWrapper && other) noexcept             = default;
    AttributeWrapper & operator=(const AttributeWrapper & other)     = default;
    AttributeWrapper & operator=(AttributeWrapper && other) noexcept = default;

    AttributeWrapper(TLVType aType, uint8_t bytes = 0, AttributeQualityEnum aQuality = AttributeQualityEnum::kMandatory) :
        type(aType), quality(aQuality), length(bytes)
    {
        switch (quality)
        {
        case AttributeQualityEnum::kMandatory:
            value = AnyType{};
            break;
        case AttributeQualityEnum::kOptional:
            value = chip::Optional<AnyType>::Missing();
            break;
        default:
            break;
        }
    }
    AttributeWrapper(TLVType aType, const AnyType & aValue, uint8_t bytes = 0,
                     AttributeQualityEnum aQuality = AttributeQualityEnum::kMandatory) :
        type(aType), quality(aQuality), length(bytes)
    {
        switch (quality)
        {
        case AttributeQualityEnum::kMandatory:
            value = AnyType{};
            break;
        case AttributeQualityEnum::kOptional:
            value = chip::Optional<AnyType>::Missing();
            break;
        default:
            return;
        }
        Write(aValue);
    }
    TLVType type;
    AttributeQualityEnum quality;
    uint8_t length;
    // TODO: Add support for nullable attributes
    std::variant<std::monostate, AnyType, chip::Optional<AnyType>> value = {};
    AnyType * Read() { return Visitors::AttributeWrapperRead(this); }
    CHIP_ERROR Write(const AnyType & aValue)
    {
        size_t typeIndexBeforeWrite           = value.index();
        size_t underlyingTypeIndexBeforeWrite = Read()->index();
        size_t typeIndexAfterWrite            = UINT64_MAX;
        size_t underlyingTypeIndexAfterWrite  = UINT64_MAX;

        ReturnErrorOnFailure(
            Visitors::AttributeWrapperWriteOrFail(this, typeIndexAfterWrite, underlyingTypeIndexAfterWrite, aValue));
        VerifyOrReturnError(typeIndexAfterWrite != UINT64_MAX && underlyingTypeIndexAfterWrite != UINT64_MAX, CHIP_ERROR_INTERNAL);
        VerifyOrReturnError(typeIndexBeforeWrite != typeIndexAfterWrite, CHIP_FUZZER_ERROR_ATTRIBUTE_TYPE_MISMATCH);
        VerifyOrReturnError(underlyingTypeIndexBeforeWrite != underlyingTypeIndexAfterWrite,
                            CHIP_FUZZER_ERROR_ATTRIBUTE_TYPE_MISMATCH);
        return CHIP_NO_ERROR;
    }
};

/**
 * @brief Factory class to create AttributeWrapper instances.
 *
 * The AttributeWrapper creation follows these steps:
 *
 * 1. Call the static Create method with the type, value, length and quality. This method firstly checks if given arguments are
 * supported.
 *
 * 2. If arguments are supported, TrySetAttribute is called to create the AttributeWrapper instance.
 *
 * 3. To set the attribute value, which can be either of type std::monostate (uninitialized), AnyType (mandatory) or
 * chip::Optional<AnyType>> (optional), the visitor inside TrySetAttribute checks which type of variant is being holded by the
 * argument value and, based on the quality, sets the value.
 *
 * 4. A unique_ptr to the AttributeWrapper instance is returned.
 *
 */
struct AttributeFactory
{
public:
    static std::shared_ptr<AttributeWrapper> Create(TLVType type, const AnyType & value, uint8_t length = 0,
                                                    AttributeQualityEnum quality = AttributeQualityEnum::kMandatory)
    {
        VerifyOrDie(quality != AttributeQualityEnum::kNullable);
        auto key = std::make_pair(type, length);
        for (const auto & supportedType : supportedTypes)
        {
            if (supportedType == key)
            {
                return std::make_shared<AttributeWrapper>(type, value, length, quality);
            }
        }
        return nullptr; // Default factory logic
    };

    static std::shared_ptr<AttributeWrapper> Create(TLVType type, uint8_t length = 0,
                                                    AttributeQualityEnum quality = AttributeQualityEnum::kMandatory)
    {
        return Create(type, AnyType{}, length, quality);
    };
};

} // namespace fuzzing
} // namespace chip
