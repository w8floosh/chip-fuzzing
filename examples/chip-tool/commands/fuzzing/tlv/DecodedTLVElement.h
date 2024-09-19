#pragma once
#include "../AttributeFactory.h"
#include "../ForwardDeclarations.h"
#include "../Utils.h"
#include <iostream>
namespace chip {
namespace fuzzing {
namespace TLV {
using chip::fuzzing::AttributeQualityEnum;
/**
 * @brief Encodes a TLV element with a specific type, length and tag using the C++ standard types.
 *
 * @param aType The TLV type of the element.
 * @param aBytes The byte size of the underlying C++ primitive type or the number of bytes used to represent the length (in
 * case of a string element). 0 must be used when the type has a fixed size or is a container type.
 * @param aTag The tag of the element. Defaults to Anonymous.
 */
class DecodedTLVElement
{
public:
    DecodedTLVElement() {};
    DecodedTLVElement(const DecodedTLVElement & other)                 = default;
    DecodedTLVElement(DecodedTLVElement && other) noexcept             = default;
    DecodedTLVElement & operator=(const DecodedTLVElement & other)     = default;
    DecodedTLVElement & operator=(DecodedTLVElement && other) noexcept = default;

    DecodedTLVElement(TLVType aType, uint8_t aBytes = 0, TLVTag aTag = TLVTag::Anonymous) :
        type(aType), length(aBytes), tag(aTag) {};
    DecodedTLVElement(TLVType aType, uint8_t aBytes = 0, TLVTag aTag = TLVTag::Anonymous,
                      AttributeQualityEnum aQuality = AttributeQualityEnum::kMandatory) :
        type(aType), length(aBytes), tag(aTag), quality(aQuality) {};
    /**
     * Given a DecodedTLVElement, returns the remaining length that can be written to the element.
     * @returns 0 if the element has a fixed size or is a container type. Otherwise, returns the remaining length that can be
     * written.
     */
    TLVType type    = TLVType::kTLVType_NotSpecified;
    AnyType content = {};
    uint8_t length;
    TLVTag tag;
    AttributeQualityEnum quality;

    bool IsContainer() { return std::holds_alternative<ContainerType>(content); };
    static std::shared_ptr<TLV::DecodedTLVElement> Create(TLVType type, uint8_t length = 0, TLVTag tag = TLVTag::Anonymous,
                                                          AttributeQualityEnum quality = AttributeQualityEnum::kMandatory)
    {
        auto key = std::make_pair(type, length);
        for (const auto & supportedType : supportedTypes)
        {
            if (supportedType == key)
            {
                return std::make_shared<TLV::DecodedTLVElement>(type, length, tag, quality);
            }
        }
        return nullptr; // Default factory logic
    };
    void Print(size_t indent = 0)
    {
        for (size_t i = 0; i < indent; i++)
        {
            std::cout << " ";
        }
        std::cout << "[Type: " << std::hex << static_cast<int16_t>(type) << ", Size or length: " << length << ", Tag: " << std::hex
                  << static_cast<int16_t>(tag) << " (" << (quality == AttributeQualityEnum::kMandatory ? "mandatory" : "optional")
                  << ")]" << std::endl;
        for (size_t i = 0; i < indent; i++)
        {
            std::cout << " ";
        }
        std::visit(
            [&](auto && arg) {
                using arg_t = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<arg_t, ContainerType>)
                {
                    for (const auto & element : arg)
                    {
                        std::visit(
                            [&](auto && nested) {
                                using nested_t = std::decay_t<decltype(nested)>;
                                if constexpr (std::is_same_v<nested_t, std::shared_ptr<TLV::DecodedTLVElement>>)
                                {
                                    nested->Print(indent + 2);
                                }
                                else
                                {
                                    PrintPrimitive<nested_t>(nested);
                                }
                            },
                            element);
                    }
                }
                else
                {
                    PrintPrimitive<arg_t>(arg);
                }
            },
            content);
    };

private:
    template <typename T>
    void PrintPrimitive(T value)
    {
        if constexpr (std::is_same_v<T, std::string>)
        {
            std::cout << value << std::endl;
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            std::cout << (value ? "true" : "false") << std::endl;
        }
        else if constexpr (std::is_same_v<T, char *>)
        {
            std::cout << std::string(value) << std::endl;
        }
        else if constexpr (std::is_convertible_v<T, uint64_t> || std::is_convertible_v<T, int64_t> ||
                           std::is_convertible_v<T, double> || std::is_convertible_v<T, float>)
        {
            std::cout << std::to_string(value) << std::endl;
        }
        else if constexpr (std::is_same_v<T, std::nullopt_t>)
        {
            std::cout << "null" << std::endl;
        }
        else
        {
            std::cout << "???" << std::endl;
        }
    }
};

} // namespace TLV
} // namespace fuzzing
} // namespace chip
