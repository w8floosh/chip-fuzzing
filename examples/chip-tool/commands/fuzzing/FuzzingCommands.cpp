#include "FuzzingCommands.h"
#include <numeric>
#include <string>

namespace {
inline constexpr char kRetrieveDeviceTypeCommand[] =
    "descriptor read device-type-list "; // returns device type for each endpoint of the node
inline constexpr char kRetrievePartsCommand[]          = "descriptor read parts-list ";  // returns endpoints of the node
inline constexpr char kRetrieveServerClustersCommand[] = "descriptor read server-list "; // returns clusters of all endpoints
} // namespace

namespace fuzz = chip::fuzzing;

void FuzzingCommand::ExecuteCommand(const char * command, int * status)
{
    *status = mHandler->RunFuzzing(command);
}

CHIP_ERROR
FuzzingStartCommand::RetrieveNodeDescription(NodeId id)
{

    int status = 0;
    std::string command;
    std::string commandType;

    // Get node endpoints
    commandType = kRetrievePartsCommand;
    command     = commandType.append(std::to_string(id)).append(" 0xffff");
    ExecuteCommand(command.c_str(), &status);
    VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    // Get device type for each endpoint
    commandType = kRetrieveDeviceTypeCommand;
    command     = commandType.append(std::to_string(id).append(" 0xffff"));
    ExecuteCommand(command.c_str(), &status);
    VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    // Return server clusters for each endpoint
    commandType = kRetrieveServerClustersCommand;
    command     = commandType.append(std::to_string(id).append(" 0xffff"));
    ExecuteCommand(command.c_str(), &status);
    VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::InitializeFuzzer()
{
    const fuzz::FuzzerType * kFuzzerType = fuzz::ConvertStringToFuzzerType(mFuzzerTypeArgument);
    VerifyOrReturnError(kFuzzerType != nullptr, CHIP_FUZZER_ERROR_NOT_IMPLEMENTED);

    const fuzz::FuzzingStrategy * kFuzzingStrategy = *kFuzzerType == fuzz::FuzzerType::SEED_ONLY
        ? fuzz::ConvertStringToFuzzingStrategy("none")
        : fuzz::ConvertStringToFuzzingStrategy(mFuzzingStrategyArgument);

    VerifyOrReturnError(kFuzzingStrategy != nullptr, CHIP_FUZZER_ERROR_NOT_IMPLEMENTED);

    mSeedDirectory = fs::path(mSeedDirectoryArgument);
    VerifyOrReturnError(fs::exists(mSeedDirectory), CHIP_FUZZER_FILESYSTEM_ERROR);

    if (mOutputDirectoryArgument.HasValue())
    {
        mStatefulFuzzingEnabled = true;
        mOutputDirectory.SetValue(fs::path(mOutputDirectoryArgument.Value()));
        VerifyOrReturnError(fs::exists(mOutputDirectory.Value()), CHIP_FUZZER_FILESYSTEM_ERROR);
    }

    // Fuzzer instance initialization
    switch (*kFuzzerType)
    {
    case fuzz::FuzzerType::AFL_PLUSPLUS:
        mFuzzer = new fuzz::wrappers::AFLPlusPlus(mSeedDirectory, *kFuzzingStrategy);
        break;
    case fuzz::FuzzerType::SEED_ONLY:
        // strategy is ignored
        mFuzzer = new fuzz::wrappers::SeedOnly(mSeedDirectory);
        break;
    default:
        return CHIP_FUZZER_ERROR_NOT_IMPLEMENTED;
        break;
    };

    kFuzzerType      = nullptr;
    kFuzzingStrategy = nullptr;

    VerifyOrReturnError(mFuzzer != nullptr, CHIP_FUZZER_ERROR_INITIALIZATION_FAILED);
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::RunCommand()
{
    InitializeFuzzer();

    // TODO: get dynamic node id from command line
    // Retrieve device configuration using Descriptor cluster and initialize the state
    RetrieveNodeDescription(0);
    // Get all cluster states for the node i at endpoint j
    auto * clustersMap = mFuzzer->GetDeviceStateManager()->GetClustersOnEndpoint(0, 0);
    VerifyOrReturnError(clustersMap != nullptr, CHIP_ERROR_INTERNAL);

    // Run the fuzzer: execute mIterations commands for each cluster
    for (uint32_t i = 0U; i < mIterations.Value(); i++)
    {
        for (auto cluster : *clustersMap)
        {
            int status                = 0;
            chip::ClusterId clusterId = cluster.first;

            const char * command = GenerateCommand(clusterId); // cluster.first = cluster ID
            ExecuteCommand(command, &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_UNEXPECTED_ERROR);
        }
    }

    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};

const char * FuzzingStartCommand::GenerateCommand(chip::ClusterId cluster)
{
    return mFuzzer->GenerateCommand();
};
