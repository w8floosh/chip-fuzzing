#include "DeviceStateManager.h"
#include "Oracle.h"
#include <app/tests/suites/commands/interaction_model/InteractionModel.h>
#include <filesystem>

namespace fs = std::filesystem;
namespace chip {
namespace fuzzing {

enum FuzzerType
{
    AFL_PLUSPLUS,
    Y,
    Z
};
enum FuzzingStrategy
{
    A,
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

    ~Fuzzer();

    virtual char * GenerateCommand() = 0;
    void ProcessCommandOutput(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path, CHIP_ERROR error,
                              CHIP_ERROR expectedError, const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus);
    void ProcessCommandOutput(CHIP_ERROR error, CHIP_ERROR expectedError);
    CHIP_ERROR InitNodeState(NodeId id, std::any *& nodeData);

protected:
    // TODO: Should the fuzzer log oracle outputs too?
    CHIP_ERROR ExportSeedToFile(const char * command, const chip::app::ConcreteCommandPath & dataModelPath);

private:
    FuzzingStrategy mStrategy;
    fs::path mSeedsDirectory;
    Optional<fs::path> mOutputDirectory = NullOptional;
    DeviceStateManager mDeviceStateManager;
    Oracle mOracle;
};

class AFLPlusPlus : public Fuzzer
{
public:
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy) : Fuzzer(seedsDirectory, strategy) {};
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy, fs::path outputDirectory) :
        Fuzzer(seedsDirectory, strategy, outputDirectory) {};

    ~AFLPlusPlus();

    char * GenerateCommand() override;
};

CHIP_ERROR Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory, Fuzzer ** fuzzer);

FuzzerType * ConvertStringToFuzzerType(const char * key);
FuzzingStrategy * ConvertStringToFuzzingStrategy(const char * key);
} // namespace fuzzing
} // namespace chip
