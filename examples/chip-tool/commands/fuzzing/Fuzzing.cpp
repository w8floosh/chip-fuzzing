#include "Fuzzing.h"
#include "Fuzzers.h"
#include <lib/support/jsontlv/TlvJson.h>

namespace fuzz = chip::fuzzing;

namespace {

std::unordered_map<std::string, fuzz::FuzzerType> fuzzerTypeMap({ { "afl++", fuzz::FuzzerType::AFL_PLUSPLUS },
                                                                  { "seed-only", fuzz::FuzzerType::SEED_ONLY } });
std::unordered_map<std::string, fuzz::FuzzingStrategy> fuzzingStrategyMap({ { "none", fuzz::FuzzingStrategy::NONE } });

template <typename T>
const T * GetMapElementFromKeyEnum(const std::unordered_map<std::string, T> & map, const char * key)
{
    VerifyOrReturnValue(std::is_enum<T>::value, nullptr);

    auto found = map.find(std::string(key));
    VerifyOrReturnValue(found != map.end(), nullptr);

    return &(found->second);
}
} // namespace

void fuzz::Fuzzer::ProcessCommandOutput(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path, CHIP_ERROR error,
                                        CHIP_ERROR expectedError, const chip::app::StatusIB & status,
                                        chip::app::StatusIB expectedStatus)
{
    if (data == nullptr)
        return;
    {
        chip::TLV::TLVReader outputReader;
        outputReader.Init(*data);

        // TODO: Manually parse the TLV data and call mOracle.Consume() on every attribute/path scanned
        // TODO: For each error, log a line showing command, error type and error description
    }
}

void fuzz::Fuzzer::ProcessCommandOutput(CHIP_ERROR error, CHIP_ERROR expectedError) {}

CHIP_ERROR fuzz::Fuzzer::ExportSeedToFile(const char * command, const chip::app::ConcreteCommandPath & dataModelPath)
{
    namespace fs = std::filesystem;

    auto now    = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    // Create seed hash from current timestamp
    std::hash<std::string> hasher;
    size_t hashedValue = hasher(std::to_string(now_ms.count()));

    std::string fileName(std::to_string(hashedValue)); // Convert hash to hex string

    fs::path seedExportDirectory = mSeedsDirectory / std::to_string(dataModelPath.mClusterId);
    // Insert the command in the file at path "seeds/<clusterId>/<hashedValue>"
    if (!fs::exists(seedExportDirectory))
    {
        VerifyOrReturnError(!fs::create_directories(seedExportDirectory), CHIP_FUZZER_FILESYSTEM_ERROR);
    }

    auto fd = fopen((seedExportDirectory / fileName).c_str(), "w");
    VerifyOrReturnError(nullptr != fd, CHIP_FUZZER_FILESYSTEM_ERROR);

    fwrite(command, sizeof(char), strlen(command), fd);

    auto rv = fclose(fd);
    VerifyOrReturnError(EOF != rv, CHIP_FUZZER_FILESYSTEM_ERROR);

    ChipLogProgress(chipTool, "Logged well-formed command: %s", command);

    return CHIP_NO_ERROR;
}

const fuzz::FuzzerType * fuzz::ConvertStringToFuzzerType(const char * key)
{
    return GetMapElementFromKeyEnum<fuzz::FuzzerType>(fuzzerTypeMap, key);
}

const fuzz::FuzzingStrategy * fuzz::ConvertStringToFuzzingStrategy(const char * key)
{
    return GetMapElementFromKeyEnum<fuzz::FuzzingStrategy>(fuzzingStrategyMap, key);
}
