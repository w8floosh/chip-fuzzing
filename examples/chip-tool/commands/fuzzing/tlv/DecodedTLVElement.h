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
};

class DecodedTLVElementPrettyPrinter
{
public:
    DecodedTLVElementPrettyPrinter(std::shared_ptr<TLV::DecodedTLVElement> element) : mElement(element) {}

    void Print() { PrintDecodedElement(mElement); }

private:
    std::shared_ptr<TLV::DecodedTLVElement> mElement;
    template <typename T>
    void PrintDecodedPrimitiveElement(T value, size_t indent)
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

    void PrintDecodedContainerElement(ContainerType & container, size_t indent)
    {
        for (const auto & element : container)
        {
            std::visit(
                [&](auto && arg) {
                    using nested_t = std::decay_t<decltype(arg)>;
                    if constexpr (std::is_same_v<nested_t, std::shared_ptr<TLV::DecodedTLVElement>>)
                    {
                        PrintDecodedElement(arg, indent + 2);
                    }
                    else
                    {
                        PrintDecodedPrimitiveElement<nested_t>(arg, indent + 2);
                    }
                },
                element);
        }
        if (container.size() == 0)
        {
            std::cout << "}";
        }
        else
        {
            Indent(indent);
            std::cout << "}" << std::endl;
        }
    }

    void PrintDecodedElement(std::shared_ptr<TLV::DecodedTLVElement> element, size_t indent = 0)
    {
        VerifyOrDie(element != nullptr);
        std::visit(
            [&](auto && arg) {
                using arg_t = std::decay_t<decltype(arg)>;
                PrintDecodedElementMetadata(element, indent);

                if constexpr (std::is_same_v<arg_t, ContainerType>)
                {
                    PrintDecodedContainerElement(arg, indent);
                }
                else
                {
                    PrintDecodedPrimitiveElement<arg_t>(arg, indent);
                }
            },
            element->content);
    };

    void PrintDecodedElementMetadata(std::shared_ptr<TLV::DecodedTLVElement> element, size_t indent = 0)
    {
        VerifyOrDie(element != nullptr);
        Indent(indent);
        std::cout << "[Type: 0x" << std::hex << static_cast<int16_t>(element->type)
                  << ", Size or length: " << static_cast<uint16_t>(element->length) << ", Tag: 0x" << std::hex
                  << static_cast<int16_t>(element->tag) << " ("
                  << (element->quality == AttributeQualityEnum::kMandatory ? "mandatory" : "optional");
        std::visit(
            [&](auto && arg) {
                using arg_t = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<arg_t, ContainerType>)
                {

                    std::cout << "), size: " << arg.size() << "] = {" << std::endl;
                }
                else
                {
                    std::cout << ")] = ";
                }
            },
            element->content);
    }
};
} // namespace TLV
} // namespace fuzzing
} // namespace chip
