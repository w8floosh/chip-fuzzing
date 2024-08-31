#pragma once
#include "DeviceStateManager.h"
#include "Error.h"
#include "Oracle.h"
#include <app/tests/suites/commands/interaction_model/InteractionModel.h>
#include <filesystem>

namespace fs = std::filesystem;
namespace chip {
namespace fuzzing {

enum FuzzerType
{
    AFL_PLUSPLUS,
    SEED_ONLY,
    Z
};
enum FuzzingStrategy
{
    NONE,
    B,
    C
};

class Fuzzer
{
public:
    Fuzzer(fs::path seedsDirectory, FuzzingStrategy strategy) : mSeedsDirectory(seedsDirectory), mStrategy(strategy) {};
    Fuzzer(fs::path seedsDirectory, FuzzingStrategy strategy, fs::path outputDirectory) :
        mSeedsDirectory(seedsDirectory), mStrategy(strategy)
    {
        mOutputDirectory.SetValue(outputDirectory);
    };
    virtual ~Fuzzer() = default;

    virtual const char * GenerateCommand() = 0;
    void ProcessCommandOutput(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path, CHIP_ERROR error,
                              CHIP_ERROR expectedError, const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus);
    void ProcessCommandOutput(CHIP_ERROR error, CHIP_ERROR expectedError);
    DeviceStateManager * GetDeviceStateManager() { return &mDeviceStateManager; }

protected:
    fs::path mSeedsDirectory;
    Optional<fs::path> mOutputDirectory = NullOptional;
    DeviceStateManager mDeviceStateManager;
    Oracle mOracle;

    // TODO: Should the fuzzer log oracle outputs too?
    CHIP_ERROR ExportSeedToFile(const char * command, const chip::app::ConcreteCommandPath & dataModelPath);

private:
    FuzzingStrategy mStrategy;
};

const FuzzerType * ConvertStringToFuzzerType(const char * key);
const FuzzingStrategy * ConvertStringToFuzzingStrategy(const char * key);
} // namespace fuzzing
} // namespace chip
