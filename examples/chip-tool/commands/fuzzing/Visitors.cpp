#include "Visitors.h"
#include "Fuzzing.h"
#include "tlv/DecodedTLVElement.h"

namespace Visitors = chip::fuzzing::Visitors;

template <typename T>
T Visitors::TLV::ConvertToIdType(std::shared_ptr<DecodedTLVElement> element)
{
    uint32_t primitive = TryConvertPrimitiveType<uint32_t>(element);
    if (primitive == std::numeric_limits<uint32_t>::max())
    {
        if constexpr (std::is_same_v<T, EndpointId>)
        {
            return kInvalidEndpointId;
        }
        else
        {
            return kInvalidClusterId;
        }
    }
    return static_cast<T>(primitive);
}
template chip::EndpointId Visitors::TLV::ConvertToIdType<chip::EndpointId>(std::shared_ptr<DecodedTLVElement> element);
template chip::ClusterId Visitors::TLV::ConvertToIdType<chip::ClusterId>(std::shared_ptr<DecodedTLVElement> element);

template <typename T>
T Visitors::TLV::TryConvertPrimitiveType(std::shared_ptr<DecodedTLVElement> element)
{
    VerifyOrDie(!std::holds_alternative<ContainerType>(element->content));
    return std::visit(
        [](auto && arg) -> T {
            using arg_t = std::decay_t<decltype(arg)>;
            if constexpr (std::is_convertible_v<arg_t, T>)
            {
                return static_cast<T>(arg);
            }
            else
            {
                // TODO: Consider another solution without exceptions
                return std::numeric_limits<T>::max();
            }
        },
        element->content);
}
template uint32_t Visitors::TLV::TryConvertPrimitiveType<uint32_t>(std::shared_ptr<DecodedTLVElement> element);

void Visitors::TLV::PrintDecodedElement(DecodedTLVElementPrettyPrinter * printer, std::shared_ptr<DecodedTLVElement> element,
                                        size_t indent)
{
    std::visit(
        [&](auto && arg) {
            using arg_t = std::decay_t<decltype(arg)>;
            printer->PrintDecodedElementMetadata(element, indent);

            if constexpr (std::is_same_v<arg_t, ContainerType>)
            {
                printer->PrintDecodedContainerElement(arg, indent);
            }
            else
            {
                printer->PrintDecodedPrimitiveElement<arg_t>(arg, indent);
            }
        },
        element->content);
}

void Visitors::TLV::FinalizePrintDecodedElementMetadata(DecodedTLVElementPrettyPrinter * printer,
                                                        std::shared_ptr<DecodedTLVElement> element, size_t indent)
{
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

template <typename T>
void Visitors::TLV::ProcessDescriptorClusterResponse(std::shared_ptr<DecodedTLVElement> decoded,
                                                     const chip::app::ConcreteDataAttributePath & path, NodeId node)
{
    // decoded is a structure which first element is an array (container inside root container)
    std::visit(
        [&](auto && arg) {
            using arg_t = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<arg_t, ContainerType>)
            {
                VerifyOrReturn(std::holds_alternative<ContainerType>(arg[0]->content));
                auto container = std::get<ContainerType>(arg[0]->content);
                for (const auto & element : container)
                {
                    auto deviceState = fuzz::Fuzzer::GetInstance()->GetDeviceStateManager();
                    if constexpr (std::is_same_v<T, EndpointId>)
                    {
                        deviceState->Add(node, ConvertToIdType<EndpointId>(element));
                    }
                    else
                    {
                        // This case also applies to the DeviceTypeId: both types are uint32_t
                        deviceState->Add(node, path.mEndpointId, ConvertToIdType<ClusterId>(element));
                    }
                }
            }
        },
        decoded->content);
}

template void Visitors::TLV::ProcessDescriptorClusterResponse<chip::EndpointId>(std::shared_ptr<DecodedTLVElement> decoded,
                                                                                const chip::app::ConcreteDataAttributePath & path,
                                                                                NodeId node);
template void Visitors::TLV::ProcessDescriptorClusterResponse<chip::ClusterId>(std::shared_ptr<DecodedTLVElement> decoded,
                                                                               const chip::app::ConcreteDataAttributePath & path,
                                                                               NodeId node);

CHIP_ERROR
Visitors::TLV::PushToContainer(std::shared_ptr<DecodedTLVElement> element, std::shared_ptr<DecodedTLVElement> dst)
{
    return std::visit(
        [&](auto & container) -> CHIP_ERROR {
            using T = std::decay_t<decltype(container)>;
            if constexpr (std::is_same_v<T, ContainerType>)
            {
                container.push_back(std::move(element));
                return CHIP_NO_ERROR;
            }
            else
                return CHIP_ERROR_WRONG_TLV_TYPE;
        },
        dst->content);
}

fuzz::AnyType * Visitors::AttributeWrapperRead(AttributeWrapper * attribute)
{
    return std::visit(
        [&](auto & v) -> AnyType * {
            using T = std::decay_t<decltype(v)>; // T is the type of the variant
            if constexpr (std::is_same_v<T, AnyType>)
            {
                return &v;
            }
            else if constexpr (std::is_same_v<T, chip::Optional<AnyType>>)
            {
                VerifyOrReturnValue(v.HasValue(), nullptr);
                return &v.Value();
            }
            else
                return nullptr;
        },
        attribute->value);
}

CHIP_ERROR Visitors::AttributeWrapperWriteOrFail(AttributeWrapper * attribute, size_t & typeIndexAfterWrite,
                                                 size_t underlyingTypeIndexAfterWrite, const AnyType & aValue)
{
    return std::visit(
        [&](const auto & v) {
            using T = std::decay_t<decltype(attribute->value)>; // T is the type of the variant of the value holder (std::monostate,
                                                                // AnyType or chip::Optional<AnyType>)
            using VT = std::decay_t<decltype(v)>; // VT is the type of the variant of the argument (one of the PrimitiveType
                                                  // variants or ContainerType)
            if constexpr (std::is_same_v<T, AnyType>)
            {
                attribute->value = std::get<VT>(v);
            }
            else if constexpr (std::is_same_v<T, chip::Optional<AnyType>>)
            {
                attribute->value = chip::Optional<VT>::Value(std::get<VT>(v));
            }
            else
            {
                return CHIP_ERROR_INTERNAL;
            }
            typeIndexAfterWrite           = attribute->value.index();
            underlyingTypeIndexAfterWrite = attribute->Read()->index();
            return CHIP_NO_ERROR;
        },
        aValue);
}

std::string Visitors::AttributeValueAsString(const AnyType * attr)
{
    return "";
    // VerifyOrReturnValue(attr != nullptr, std::string("null"));
    // return std::visit(
    //     [&](auto & v) {
    //         using T = std::decay_t<decltype(v)>;
    //         if constexpr (std::is_same_v<T, bool>)
    //         {
    //             return v ? "true" : "false";
    //         }
    //         else if constexpr (std::is_same_v<T, std::string>)
    //         {
    //             return v;
    //         }
    //         else if constexpr (std::is_same_v<T, chip::ByteSpan>)
    //         {
    //             return std::string(v.data(), v.size());
    //         }
    //         else if constexpr (std::is_same_v<T, chip::Optional<AnyType>>)
    //     },
    //     *attr);
}

std::string Visitors::AttributeTypeAsString(const AnyType * attr)
{
    VerifyOrReturnValue(attr != nullptr, std::string("nullable"));
    return std::visit(
        [&](auto & v) -> std::string {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, bool>)
            {
                return v ? std::string("true") : std::string("false");
            }
            else if constexpr (std::is_same_v<T, char *>)
            {
                return std::string("byte string");
            }
            else if constexpr (std::is_same_v<T, uint8_t>)
            {
                return std::string("unsigned integer 1");
            }
            else if constexpr (std::is_same_v<T, uint16_t>)
            {
                return std::string("unsigned integer 2");
            }
            else if constexpr (std::is_same_v<T, uint32_t>)
            {
                return std::string("unsigned integer 4");
            }
            else if constexpr (std::is_same_v<T, uint64_t>)
            {
                return std::string("unsigned integer 8");
            }
            else if constexpr (std::is_same_v<T, int8_t>)
            {
                return std::string("signed integer 1");
            }
            else if constexpr (std::is_same_v<T, int16_t>)
            {
                return std::string("signed integer 2");
            }
            else if constexpr (std::is_same_v<T, int32_t>)
            {
                return std::string("signed integer 4");
            }
            else if constexpr (std::is_same_v<T, int64_t>)
            {
                return std::string("signed integer 8");
            }
            else if constexpr (std::is_same_v<T, float>)
            {
                return std::string("float");
            }
            else if constexpr (std::is_same_v<T, double>)
            {
                return std::string("double");
            }
            else if constexpr (std::is_same_v<T, std::string>)
            {
                return std::string("utf8 string");
            }
            else if constexpr (std::is_same_v<T, ContainerType>)
            {
                return std::string("container");
            }
            else if constexpr (std::is_same_v<T, std::nullopt_t>)
            {
                // TODO: Find a way to retrieve null values underlying type
                return std::string("nullable");
            }
            else
                return std::string("unknown");
        },
        *attr);
}
