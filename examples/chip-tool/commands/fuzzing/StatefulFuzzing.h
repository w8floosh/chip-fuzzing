#include "Fuzzing.h"
#include <vector>

namespace fs = std::filesystem;
namespace chip {
namespace fuzzing {
namespace stateful {
class Fuzzer : public fuzzing::Fuzzer
{
public:
    Fuzzer(fs::path seedsDirectory, FuzzingStrategy strategy, chip::Optional<fs::path> stateLogExportDirectory) :
        fuzzing::Fuzzer(seedsDirectory, strategy), mLogExportDirectory(stateLogExportDirectory) {};
    ~Fuzzer();

private:
    std::unordered_map<chip::ClusterId, ClusterState> mFuzzedDeviceState;
    chip::Optional<fs::path> mLogExportDirectory;
};

class AFLPlusPlus : public Fuzzer
{
public:
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy, chip::Optional<fs::path> stateLogExportDirectory) :
        Fuzzer(seedsDirectory, strategy, stateLogExportDirectory) {};
    ~AFLPlusPlus();

    char * GenerateCommand() override;
    CHIP_ERROR ProcessCommandExitStatus(const char * const & command, std::any output) override;
};

CHIP_ERROR Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory,
                chip::Optional<fs::path> stateLogExportDirectory, fuzzing::Fuzzer ** fuzzer);

} // namespace stateful
} // namespace fuzzing
} // namespace chip
