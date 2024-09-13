#include "../Fuzzing.h"
// TODO: Move this to implementation file
#include "TypeMapping.h"
#include <app/tests/integration/common.cpp>

namespace chip {
namespace fuzzing {
namespace TLV {
class TLVDataPayloadHelper
{
public:
    TLVDataPayloadHelper(chip::TLV::TLVReader * data) { mPayloadReader.Init(*data); }

    void Print() { PrettyPrint(); }

    template <typename T, typename std::enable_if<std::is_invocable_v<decltype(&T::LogPath), T>>::type * = nullptr>
    void Print(const T & metadata)
    {
        metadata.LogPath();
        PrettyPrint();
    }

    template <typename T, typename std::enable_if<std::is_same_v<T, AttributeId> || std::is_same_v<T, CommandId>>::type * = nullptr>
    void Print(const EndpointId endpoint, const ClusterId cluster, const T leaf)
    {
        std::string leafType = std::is_same_v<T, AttributeId> ? "Attribute" : "Command";
        std::cout << "Endpoint: " << std::to_string(endpoint) << " Cluster: " << std::to_string(endpoint) << " " << leafType << ":"
                  << leaf;
        PrettyPrint();
    }

    CHIP_ERROR Decode(DecodedTLVElement<TLVType::kTLVType_Structure> & output);
    CHIP_ERROR Encode(DecodedTLVElement<TLVType::kTLVType_Structure> & src);
    CHIP_ERROR WriteToDeviceState(DecodedTLVElement<TLVType::kTLVType_Structure> & src, DeviceStateManager & deviceStateManager);
    CHIP_ERROR LoadClusterSnapshot(fs::path src, ClusterState & state, bool fromJSON = false);
    CHIP_ERROR LoadClusterSnapshot(fs::path src, chip::TLV::TLVWriter & writer, bool fromJSON = false);
    CHIP_ERROR LoadClusterSnapshot(fs::path src, std::string & jsonStr, bool fromJSON = false);
    CHIP_ERROR SaveClusterSnapshot(fs::path dst, ClusterState & state, bool toJSON = false);
    CHIP_ERROR SaveClusterSnapshot(fs::path dst, ClusterState & state, std::string lastCommand, bool toJSON = false);
    CHIP_ERROR SaveClusterSnapshot(fs::path dst, ClusterState & state, std::vector<std::string> commandHistory,
                                   bool toJSON = false);

private:
    chip::TLV::TLVReader mPayloadReader;
    chip::TLV::TLVWriter mPayloadWriter;
    chip::Protocols::InteractionModel::MsgType mMessageType;
    void PrettyPrint()
    {
        chip::TLV::TLVReader printBuffer;
        printBuffer.Init(mPayloadReader);
        chip::TLV::Debug::Dump(printBuffer, TLVPrettyPrinter);
    }
    auto GetParser();
};

} // namespace TLV
} // namespace fuzzing
} // namespace chip
