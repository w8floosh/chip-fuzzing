#include "DeviceStateManager.h"
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
    ~Fuzzer();

    virtual char * GenerateCommand()                                                           = 0;
    virtual CHIP_ERROR ProcessCommandExitStatus(const char * const & command, std::any output) = 0;
    CHIP_ERROR InitNodeState(NodeId id, const std::any * const & nodeData);

private:
    FuzzingStrategy mStrategy;
    fs::path mSeedsDirectory;
    DeviceStateManager mDeviceStateManager;
};

class AFLPlusPlus : public Fuzzer
{
public:
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy) : Fuzzer(seedsDirectory, strategy) {};
    ~AFLPlusPlus();

    char * GenerateCommand() override;
    CHIP_ERROR ProcessCommandExitStatus(const char * const & command, std::any output) override;
};

CHIP_ERROR Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory, Fuzzer ** fuzzer);

FuzzerType * ConvertStringToFuzzerType(const char * key);
FuzzingStrategy * ConvertStringToFuzzingStrategy(const char * key);
} // namespace fuzzing
} // namespace chip
