#include <any> // to remove
#include <app-common/zap-generated/cluster-objects.h>
#include <filesystem>
#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <unordered_map>

namespace fs = std::filesystem;
namespace chip {
namespace fuzzing {
std::unordered_map<std::string, FuzzerType> fuzzerTypeMap           = { { "afl++", FuzzerType::AFL_PLUSPLUS } };
std::unordered_map<std::string, FuzzingStrategy> fuzzingStrategyMap = {};

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
    Fuzzer(fs::path seedsDirectory, FuzzingStrategy strategy) { mStrategy = strategy; };
    ~Fuzzer();
    virtual char * GenerateCommand() = 0;

private:
    FuzzingStrategy mStrategy;
    char * Mutate(char * command);
};

class AFLPlusPlus : public Fuzzer
{
public:
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy) : Fuzzer(seedsDirectory, strategy) {};
    ~AFLPlusPlus();

    char * GenerateCommand() override;
};

CHIP_ERROR Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory, Fuzzer ** fuzzer);

FuzzerType * ConvertStringToFuzzerType(const char * key);
FuzzingStrategy * ConvertStringToFuzzingStrategy(const char * key)
{
    if (key == nullptr)
    {
        return nullptr;
    }
    std::unordered_map<std::string, FuzzingStrategy>::iterator found = fuzzingStrategyMap.find(std::string(key));
    if (found == fuzzingStrategyMap.end())
    {
        return nullptr;
    }
    return &(found->second);
}
} // namespace fuzzing
} // namespace chip
