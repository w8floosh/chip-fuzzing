#include "Visitors.h"
#include "Fuzzing.h"
#include "tlv/DecodedTLVElement.h"

namespace Visitors = chip::fuzzing::Visitors;

void Visitors::TLV::PrintElementInDecodedContainerElement(DecodedTLVElementPrettyPrinter * printer, ContainerInnerType element,
                                                          size_t indent)
{
    std::visit(
        [&](auto && arg) {
            using nested_t = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<nested_t, std::shared_ptr<DecodedTLVElement>>)
            {
                printer->PrintDecodedElement(arg, indent + 2);
            }
            else
            {
                printer->PrintDecodedPrimitiveElement<nested_t>(arg, indent + 2);
            }
        },
        element);
}

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

void Visitors::TLV::PrintDecodedElementMetadata(DecodedTLVElementPrettyPrinter * printer,
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
    std::visit(
        [&](auto && arg) {
            using arg_t = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<arg_t, ContainerType>)
            {
                // device type list is retrieved for each endpoint, but each endpoint can have only one device type (singleton
                // array)
                auto list      = std::get<std::shared_ptr<DecodedTLVElement>>(arg[0]);
                auto container = std::get<ContainerType>(list->content);
                for (const auto & element : container)
                {
                    auto deviceState = fuzz::Fuzzer::GetInstance()->GetDeviceStateManager();
                    if constexpr (std::is_same_v<T, EndpointId>)
                    {
                        deviceState->Add(node, IdTypeConverter<EndpointId>(element));
                    }
                    else if constexpr (std::is_same_v<T, ClusterId>)
                    {
                        // This case also applies to the DeviceTypeId: both types are uint32_t
                        deviceState->Add(node, path.mEndpointId, IdTypeConverter<ClusterId>(element));
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
