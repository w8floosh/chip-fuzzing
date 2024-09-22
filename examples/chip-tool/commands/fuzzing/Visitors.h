#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"

namespace fuzz = chip::fuzzing;
namespace chip {
namespace fuzzing {
namespace Visitors {
using DecodedTLVElement              = chip::fuzzing::TLV::DecodedTLVElement;
using DecodedTLVElementPrettyPrinter = chip::fuzzing::TLV::DecodedTLVElementPrettyPrinter;

namespace TLV {

void PrintElementInDecodedContainerElement(DecodedTLVElementPrettyPrinter * printer, ContainerInnerType element, size_t indent);
void PrintDecodedElement(DecodedTLVElementPrettyPrinter * printer, std::shared_ptr<DecodedTLVElement> element, size_t indent);
void PrintDecodedElementMetadata(DecodedTLVElementPrettyPrinter * printer, std::shared_ptr<DecodedTLVElement> element,
                                 size_t indent);
CHIP_ERROR
PushToContainer(std::shared_ptr<DecodedTLVElement> element, std::shared_ptr<DecodedTLVElement> dst);

template <typename T>
T IdTypeConverter(ContainerInnerType id)
{
    return std::visit(
        [](auto && arg) -> T {
            using arg_t = std::decay_t<decltype(arg)>;
            if constexpr (std::is_convertible_v<arg_t, T>)
            {
                return static_cast<T>(arg);
            }
            else if constexpr (std::is_same_v<T, EndpointId>)
            {
                return kInvalidEndpointId;
            }
            else if constexpr (std::is_same_v<T, ClusterId>)
            {
                // This case also applies to the DeviceTypeId: both types are uint32_t
                return kInvalidClusterId;
            }
        },
        id);
}

template <typename T>
T PrimitiveElementContentConverter(std::shared_ptr<DecodedTLVElement> element)
{
    VerifyOrDie(!std::holds_alternative<std::shared_ptr<DecodedTLVElement>>(element->content));
    return std::visit(
        [](auto && arg) -> T {
            using arg_t = std::decay_t<decltype(arg)>;
            if constexpr (std::is_convertible_v<arg_t, T>)
            {
                return static_cast<T>(arg);
            }
            else
                throw std::runtime_error("Invalid variant type conversion");
        },
        std::get<std::shared_ptr<DecodedTLVElement>>(element->content)->content);
}

template <typename T>
void ProcessDescriptorClusterResponse(std::shared_ptr<DecodedTLVElement> decoded, const chip::app::ConcreteDataAttributePath & path,
                                      NodeId node);

extern template void ProcessDescriptorClusterResponse<EndpointId>(std::shared_ptr<DecodedTLVElement> decoded,
                                                                  const chip::app::ConcreteDataAttributePath & path, NodeId node);
extern template void ProcessDescriptorClusterResponse<ClusterId>(std::shared_ptr<DecodedTLVElement> decoded,
                                                                 const chip::app::ConcreteDataAttributePath & path, NodeId node);
} // namespace TLV

AnyType * AttributeWrapperRead(AttributeWrapper * attribute);
CHIP_ERROR AttributeWrapperWriteOrFail(AttributeWrapper * attribute, size_t & typeIndexAfterWrite,
                                       size_t underlyingTypeIndexAfterWrite, const AnyType & aValue);

} // namespace Visitors
} // namespace fuzzing
} // namespace chip
