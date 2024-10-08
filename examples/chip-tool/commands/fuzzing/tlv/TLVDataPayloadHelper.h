#pragma once
#include "../DeviceStateManager.h"
#include "../ForwardDeclarations.h"
#include "DecodedTLVElement.h"

namespace chip {
namespace fuzzing {
namespace TLV {

inline TLVTag ExtractTagFromControlByte(uint16_t controlByte)
{
    // Bitwise AND with 0xE0 constant only takes the 3 most significant bits of the control byte, reserved to tag control
    return static_cast<TLVTag>(controlByte & 0xE0);
};

inline uint8_t ExtractSizeFromControlByte(TLVType type, uint16_t controlByte)
{
    switch (type)
    {
    case TLVType::kTLVType_Boolean:
    case TLVType::kTLVType_Structure:
    case TLVType::kTLVType_Array:
    case TLVType::kTLVType_List:
    case TLVType::kTLVType_Null: {
        return 0;
    }
    default: {
        // Bitwise AND with 0x3 constant only takes the 2 least significant bits of the control byte, reserved to size control
        return 1 << (controlByte & 0x3);
    }
    }
};

/**
 * @brief Helper class to decode and encode TLV data payloads coming from response callbacks.
 */
class TLVDataPayloadHelper
{
public:
    TLVDataPayloadHelper(chip::TLV::TLVReader * data) { mPayloadReader.Init(*data); }

    CHIP_ERROR Decode(std::shared_ptr<DecodedTLVElement> output);
    CHIP_ERROR Encode(std::shared_ptr<DecodedTLVElement> src);
    CHIP_ERROR WriteToDeviceState(std::shared_ptr<DecodedTLVElement> && src, AttributeState & attributeState);
    CHIP_ERROR PushToContainer(std::shared_ptr<DecodedTLVElement> && element, std::shared_ptr<DecodedTLVElement> dst);

    void Print() { PrettyPrint(); }

    template <typename T, typename std::enable_if<std::is_invocable_v<decltype(&T::LogPath), T>>::type * = nullptr>
    void Print(const T & metadata)
    {
        metadata.LogPath();
        PrettyPrint();
    }

    template <typename T,
              typename std::enable_if<std::is_same_v<T, chip::AttributeId> || std::is_same_v<T, chip::CommandId>>::type * = nullptr>
    void Print(EndpointId endpoint, ClusterId cluster, const T leaf)
    {
        std::string leafType = std::is_same_v<T, AttributeId> ? "Attribute" : "Command";
        std::cout << "Endpoint: " << std::to_string(endpoint) << " Cluster: " << std::to_string(endpoint) << " " << leafType << ":"
                  << leaf;
        PrettyPrint();
    }

private:
    chip::TLV::TLVReader mPayloadReader;
    chip::TLV::TLVWriter mPayloadWriter;
    chip::Protocols::InteractionModel::MsgType mMessageType;
    CHIP_ERROR DecodePrimitive(TLVType dstType, uint8_t dstBytes, std::shared_ptr<DecodedTLVElement> output);
    void PrettyPrint();
};

} // namespace TLV
} // namespace fuzzing
} // namespace chip
