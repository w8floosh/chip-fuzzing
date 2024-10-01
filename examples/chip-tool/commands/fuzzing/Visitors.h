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

void PrintDecodedElement(DecodedTLVElementPrettyPrinter * printer, std::shared_ptr<DecodedTLVElement> element, size_t indent);
void FinalizePrintDecodedElementMetadata(DecodedTLVElementPrettyPrinter * printer, std::shared_ptr<DecodedTLVElement> element,
                                         size_t indent);
CHIP_ERROR
PushToContainer(std::shared_ptr<DecodedTLVElement> element, std::shared_ptr<DecodedTLVElement> dst);

template <typename T>
T ConvertToIdType(std::shared_ptr<DecodedTLVElement> id);
extern template EndpointId ConvertToIdType<EndpointId>(std::shared_ptr<DecodedTLVElement> id);
extern template ClusterId ConvertToIdType<ClusterId>(std::shared_ptr<DecodedTLVElement> id);

// TODO: It is useful to template this function to allow for more types to be converted?
template <typename T>
T TryConvertPrimitiveType(std::shared_ptr<DecodedTLVElement> element);
extern template uint32_t TryConvertPrimitiveType<uint32_t>(std::shared_ptr<DecodedTLVElement> element);

template <typename T>
void ProcessDescriptorClusterResponse(std::shared_ptr<DecodedTLVElement> decoded, const chip::app::ConcreteDataAttributePath & path,
                                      NodeId node);

extern template void ProcessDescriptorClusterResponse<EndpointId>(std::shared_ptr<DecodedTLVElement> decoded,
                                                                  const chip::app::ConcreteDataAttributePath & path, NodeId node);
extern template void ProcessDescriptorClusterResponse<ClusterId>(std::shared_ptr<DecodedTLVElement> decoded,
                                                                 const chip::app::ConcreteDataAttributePath & path, NodeId node);
} // namespace TLV

const AnyType & AttributeWrapperRead(AttributeWrapper * attribute);
CHIP_ERROR AttributeWrapperWriteOrFail(AttributeWrapper * attribute, size_t & typeIndexAfterWrite,
                                       size_t & underlyingTypeIndexAfterWrite, AnyType && aValue);

std::string AttributeValueAsString(const AnyType & attr);
std::string AttributeTypeAsString(const AnyType & attr);

} // namespace Visitors
} // namespace fuzzing
} // namespace chip
