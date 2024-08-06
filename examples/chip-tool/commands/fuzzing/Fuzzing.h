#include <any>
#include <app-common/zap-generated/cluster-objects.h>
#include <filesystem>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <unordered_map>

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

private:
    FuzzingStrategy mStrategy;
    fs::path mSeedsDirectory;
    char * Mutate(char * command);
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
