#include "Visitors.h"
#include "Fuzzing.h"
#include "tlv/DecodedTLVElement.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>

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
                std::cout << "), size: " << std::dec << arg.size() << "] = {" << std::endl;
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
                    auto * deviceState = fuzz::Fuzzer::GetInstance()->GetDeviceStateManager();
                    if constexpr (std::is_same_v<T, EndpointId>)
                    {
                        deviceState->Add(node, ConvertToIdType<EndpointId>(element));
                    }
                    else if constexpr (std::is_same_v<T, uint32_t>)
                    {
                        /**
                         * This case applies to both DeviceTypeId and ClusterId: both types are uint32_t.
                         * "element" may be an array of DeviceTypeStruct typed objects:
                         * [
                         *   {
                         *     deviceType: int,
                         *     revision: int
                         *   }
                         * ]
                         * We only really care about the first array element at the moment
                         */

                        // Processing testing clusters is not useful and may lead to errors.

                        if (path.mAttributeId == chip::app::Clusters::Descriptor::Attributes::DeviceTypeList::Id)
                        {
                            VerifyOrDie(std::holds_alternative<ContainerType>(element->content));
                            auto deviceTypeStruct   = std::get<ContainerType>(element->content);
                            DeviceTypeId deviceType = ConvertToIdType<DeviceTypeId>(deviceTypeStruct[0]);
                            uint16_t revision       = static_cast<uint16_t>(std::get<uint8_t>(deviceTypeStruct[1]->content));
                            deviceState->Add(node, path.mEndpointId, DeviceTypeStruct{ deviceType, revision });
                        }
                        else
                        {
                            ClusterId cluster = ConvertToIdType<ClusterId>(element);
                            // TODO: Get cluster revision dynamically
                            if (IsManufacturerSpecificTestingCluster(cluster) || cluster == chip::app::Clusters::Descriptor::Id)
                                continue;
                            deviceState->Add(node, path.mEndpointId, cluster);
                        }
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

const fuzz::AnyType & Visitors::AttributeWrapperRead(AttributeWrapper * attribute)
{
    return std::visit(
        [&](auto && v) -> const AnyType & {
            using T = std::decay_t<decltype(v)>; // T is the type of the variant
            if constexpr (std::is_same_v<T, chip::Optional<AnyType>>)
            {
                VerifyOrReturnValue(v.HasValue(), kInvalidValue);
                return v.Value();
            }
            else if constexpr (std::is_same_v<T, AnyType>)
                return v;
            else
                return kInvalidValue;
        },
        attribute->value);
}

CHIP_ERROR Visitors::AttributeWrapperWriteOrFail(AttributeWrapper * attribute, size_t & typeIndexAfterWrite,
                                                 size_t & underlyingTypeIndexAfterWrite, AnyType && aValue)
{

    ReturnErrorOnFailure(std::visit(
        [&](auto & v) {
            // T is the type of the variant of the value holder (std::monostate, AnyType or chip::Optional<AnyType>)
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, AnyType>)
            {
                v = std::move(aValue);
            }
            else if constexpr (std::is_same_v<T, chip::Optional<AnyType>>)
            {
                v.SetValue(std::move(aValue));
            }
            else
            {
                return CHIP_ERROR_INTERNAL;
            }
            return CHIP_NO_ERROR;
        },
        attribute->value));
    typeIndexAfterWrite           = attribute->value.index();
    underlyingTypeIndexAfterWrite = attribute->Read().index();
    return CHIP_NO_ERROR;
}

std::string Visitors::AttributeValueAsString(const AnyType & attr)
{
    VerifyOrDie(!std::holds_alternative<ContainerType>(attr));
    return std::visit(
        [&](auto & v) -> std::string {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, bool>)
            {
                return v ? std::string("true") : std::string("false");
            }
            else if constexpr (std::is_same_v<T, char *>)
            {
                return std::string(v);
            }
            else if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, uint16_t> || std::is_same_v<T, uint32_t> ||
                               std::is_same_v<T, uint64_t> || std::is_same_v<T, int8_t> || std::is_same_v<T, int16_t> ||
                               std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t> || std::is_same_v<T, float> ||
                               std::is_same_v<T, double>)
            {
                return std::to_string(v);
            }
            else if constexpr (std::is_same_v<T, std::string>)
            {
                return v;
            }
            else if constexpr (std::is_same_v<T, NullOptionalType>)
            {
                return std::string("null");
            }
            else
                return std::string("unknown");
        },
        attr);
}

std::string Visitors::AttributeTypeAsString(const AnyType & attr)
{
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
            else if constexpr (std::is_same_v<T, NullOptionalType>)
            {
                // TODO: Find a way to retrieve null values underlying type
                return std::string("nullable");
            }
            else
                return std::string("unknown");
        },
        attr);
}
