#pragma once
#include <app/tests/suites/commands/interaction_model/InteractionModel.h>
#include <filesystem>
#include <functional>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <optional>
#include <string>
#include <variant>

namespace chip {
namespace fuzzing {
#define CHIP_FUZZER_ERROR_INITIALIZATION_FAILED CHIP_APPLICATION_ERROR(0x01)
#define CHIP_FUZZER_ERROR_NOT_FOUND CHIP_APPLICATION_ERROR(0x02)
#define CHIP_FUZZER_ERROR_NOT_IMPLEMENTED CHIP_APPLICATION_ERROR(0x03)
#define CHIP_FUZZER_ERROR_NODE_SCAN_FAILED CHIP_APPLICATION_ERROR(0x04)
#define CHIP_FUZZER_FILESYSTEM_ERROR CHIP_APPLICATION_ERROR(0x05)
#define CHIP_FUZZER_UNEXPECTED_ERROR CHIP_APPLICATION_ERROR(0x06)
#define CHIP_FUZZER_ERROR_ATTRIBUTE_TYPE_MISMATCH CHIP_APPLICATION_ERROR(0x07)
#define CHIP_FUZZER_GENERIC_ERROR CHIP_APPLICATION_ERROR(0xFF)

using TLVType       = chip::TLV::TLVType;
using TLVTag        = chip::TLV::TLVTagControl;
using PrimitiveType = std::variant<bool, char *, float, double, std::nullopt_t, int8_t, int16_t, int32_t, int64_t, uint8_t,
                                   uint16_t, uint32_t, uint64_t, std::string>;

namespace fs = std::filesystem;
class Fuzzer;
class AttributeFactory;
class AttributeWrapper;
class AttributeState;
class DeviceStateManager;
class Oracle;
struct ClusterState;
struct EndpointState;
struct NodeState;
struct DeviceState;
template <class com_t, class attr_t>
struct OracleRule;

std::function<const char *(fs::path)> ConvertStringToGenerationFunction(const char * key);

namespace TLV {
class TLVDataPayloadHelper;
class DecodedTLVElement;

inline TLVTag ExtractTagFromControlByte(uint16_t controlByte);
inline uint8_t ExtractSizeFromControlByte(TLVType type, uint16_t controlByte);
} // namespace TLV
namespace generation {
const char * GenerateCommandSeedOnly(fs::path seedsDir);
}
namespace utils {
template <typename T, typename... Args>
struct ExtendedVariant;

static const std::vector<std::pair<TLVType, uint8_t>> supportedTypes;
} // namespace utils
} // namespace fuzzing
} // namespace chip
