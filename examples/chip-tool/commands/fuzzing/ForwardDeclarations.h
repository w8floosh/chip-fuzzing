#pragma once
#include <app/tests/suites/commands/interaction_model/InteractionModel.h>
#include <filesystem>
#include <functional>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
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
using PrimitiveType = std::variant<std::monostate, bool, char *, float, double, NullOptionalType, int8_t, int16_t, int32_t, int64_t,
                                   uint8_t, uint16_t, uint32_t, uint64_t, std::string>;

namespace fs = std::filesystem;
class Fuzzer;
struct AttributeFactory;
struct AttributeWrapper;
class AttributeState;
class DeviceStateManager;
class Oracle;
class OracleRule;
struct ClusterState;
struct EndpointState;
struct NodeState;
struct DeviceState;

std::function<const char *(fs::path)> ConvertStringToGenerationFunction(const char * key);

namespace TLV {
class TLVDataPayloadHelper;
class DecodedTLVElement;
class DecodedTLVElementPrettyPrinter;

inline TLVTag ExtractTagFromControlByte(uint16_t controlByte);
inline uint8_t ExtractSizeFromControlByte(TLVType type, uint16_t controlByte);
} // namespace TLV
namespace generation {
class RuntimeGrammarManager;
const char * GenerateCommandSeedOnly(fs::path seedsDir);
} // namespace generation
namespace utils {
template <typename T, typename... Args>
struct ExtendedVariant;

static const std::vector<std::pair<TLVType, uint8_t>> supportedTypes;
} // namespace utils
} // namespace fuzzing
} // namespace chip
