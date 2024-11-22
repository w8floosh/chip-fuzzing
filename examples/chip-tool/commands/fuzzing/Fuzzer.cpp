#include "Fuzzer.h"
#include "Oracle.h"
#include "Utils.h"
#include "Visitors.h"

#include <csignal>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

fuzz::Fuzzer::Fuzzer(NodeId dst, fs::path outputDirectory, size_t tests, FuzzingCommand * executor) :
    mTarget(dst), mTests(tests), mStartTime(std::chrono::system_clock::now()), mSpecificationEncoder(executor),
    mDeviceStateTracker(outputDirectory / "statedumps"), mStateMonitor(mStartTime)
{
    mOutputDirectory.SetValue(outputDirectory);
};

CHIP_ERROR fuzz::Fuzzer::ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath)
{
    namespace fs = std::filesystem;
    auto now     = std::chrono::system_clock::now();
    auto now_ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Create seed hash from current timestamp
    std::hash<std::string> hasher;
    size_t hashedValue = hasher(std::to_string(now_ms));

    std::string fileName(std::to_string(hashedValue)); // Convert hash to hex string

    fs::path seedExportDirectory = mSeedsDirectory / std::to_string(dataModelPath.mClusterId);
    // Insert the command in the file at path "<seedsDirectory>/<clusterId>/<hashedValue>"
    if (!fs::exists(seedExportDirectory))
    {
        VerifyOrReturnError(!fs::create_directories(seedExportDirectory), CHIP_FUZZER_ERROR_SYSTEM_IO);
    }

    auto fd = fopen((seedExportDirectory / fileName).c_str(), "w");
    VerifyOrReturnError(nullptr != fd, CHIP_FUZZER_ERROR_SYSTEM_IO);

    fwrite(command, sizeof(char), strlen(command), fd);

    auto rv = fclose(fd);
    VerifyOrReturnError(EOF != rv, CHIP_FUZZER_ERROR_SYSTEM_IO);

    ChipLogProgress(chipTool, "Logged well-formed command: %s", command);

    return CHIP_NO_ERROR;
}
