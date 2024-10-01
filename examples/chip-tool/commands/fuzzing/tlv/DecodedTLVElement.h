#pragma once
#include "../AttributeFactory.h"
#include "../ForwardDeclarations.h"
#include "../Utils.h"
#include "../Visitors.h"
#include <iostream>
namespace fuzz = chip::fuzzing;
namespace chip {
namespace fuzzing {
namespace TLV {
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
                      fuzz::AttributeQualityEnum aQuality = fuzz::AttributeQualityEnum::kMandatory) :
        type(aType), length(aBytes), tag(aTag), quality(aQuality) {};

    TLVType type    = TLVType::kTLVType_NotSpecified;
    AnyType content = {};
    uint8_t length;
    TLVTag tag;
    fuzz::AttributeQualityEnum quality;

    bool IsContainer() { return std::holds_alternative<ContainerType>(content); };
    static std::shared_ptr<DecodedTLVElement> Create(TLVType type, uint8_t length = 0, TLVTag tag = TLVTag::Anonymous,
                                                     fuzz::AttributeQualityEnum quality = fuzz::AttributeQualityEnum::kMandatory)
    {
        auto key = std::make_pair(type, length);
        for (const auto & supportedType : supportedTypes)
        {
            if (supportedType == key)
            {
                return std::make_shared<DecodedTLVElement>(type, length, tag, quality);
            }
        }
        return nullptr; // Default factory logic
    };
};

class DecodedTLVElementPrettyPrinter
{
public:
    DecodedTLVElementPrettyPrinter(std::shared_ptr<DecodedTLVElement> element) : mRootElement(element) {}

    void Print()
    {
        VerifyOrDie(mRootElement != nullptr);
        Visitors::TLV::PrintDecodedElement(this, mRootElement, 0);
    }

private:
    std::shared_ptr<DecodedTLVElement> mRootElement;

    friend void fuzz::Visitors::TLV::PrintDecodedElement(DecodedTLVElementPrettyPrinter * printer,
                                                         std::shared_ptr<DecodedTLVElement> element, size_t indent);
    friend void fuzz::Visitors::TLV::FinalizePrintDecodedElementMetadata(DecodedTLVElementPrettyPrinter * printer,
                                                                         std::shared_ptr<DecodedTLVElement> element, size_t indent);
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
        else if constexpr (std::is_same_v<T, NullOptionalType>)
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
            Visitors::TLV::PrintDecodedElement(this, element, indent);
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

    void PrintDecodedElementMetadata(std::shared_ptr<DecodedTLVElement> element, size_t indent = 0)
    {
        VerifyOrDie(element != nullptr);
        Indent(indent);
        std::cout << "[Type: 0x" << std::hex << static_cast<int16_t>(element->type) << std::dec
                  << ", Byte size: " << static_cast<uint16_t>(element->length) << ", Tag: 0x" << std::hex
                  << static_cast<int16_t>(element->tag) << " (" << std::dec
                  << (element->quality == fuzz::AttributeQualityEnum::kMandatory ? "mandatory" : "optional");
        Visitors::TLV::FinalizePrintDecodedElementMetadata(this, element, indent);
    }
};
} // namespace TLV
} // namespace fuzzing
} // namespace chip
