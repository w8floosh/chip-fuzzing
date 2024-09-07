#include "FuzzingCommands.h"
#include <numeric>
#include <string>

namespace {
inline constexpr char kRetrieveDeviceTypeCommand[] =
    "descriptor read device-type-list "; // returns device type for each endpoint of the node
inline constexpr char kRetrievePartsCommand[]          = "descriptor read parts-list ";  // returns endpoints of the node
inline constexpr char kRetrieveServerClustersCommand[] = "descriptor read server-list "; // returns clusters of all endpoints
inline constexpr char kSubscribeAllSubCommand[] =
    "any subscribe-all 0xffffffff 0xffffffff 0xffffffff "; // subscribes to all attributes
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
    const char * retrievalCommands[]{ kRetrievePartsCommand, kRetrieveDeviceTypeCommand, kRetrieveServerClustersCommand };

    for (auto commandType : retrievalCommands)
    {
        std::ostringstream command;
        command << commandType << std::to_string(id) << " 0xffff";
        ExecuteCommand(command.str().c_str(), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::SubscribeAll(NodeId node)
{
    int status = 0;
    std::string commandType;
    std::ostringstream command;

    commandType = kSubscribeAllSubCommand;
    command << commandType << "0 5 " << std::to_string(node) << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::InitializeFuzzer()
{
    std::function<const char *(fs::path)> kGenerationFunc = fuzz::ConvertStringToGenerationFunction(mGenerationFuncArgument);
    VerifyOrReturnError(kGenerationFunc != nullptr, CHIP_FUZZER_ERROR_NOT_IMPLEMENTED);

    mSeedDirectory = fs::path(mSeedDirectoryArgument);
    if (!fs::exists(mSeedDirectory))
    {
        VerifyOrReturnError(fs::create_directory(mSeedDirectory), CHIP_FUZZER_FILESYSTEM_ERROR);
    }

    if (mOutputDirectoryArgument.HasValue())
    {
        mStatefulFuzzingEnabled = true;
        mOutputDirectory.SetValue(fs::path(mOutputDirectoryArgument.Value()));
        VerifyOrReturnError(fs::exists(mOutputDirectory.Value()), CHIP_FUZZER_FILESYSTEM_ERROR);
        fuzz::Fuzzer::Initialize(mSeedDirectory, kGenerationFunc, mOutputDirectory.Value());
    }
    else
    {
        fuzz::Fuzzer::Initialize(mSeedDirectory, kGenerationFunc);
    }

    kGenerationFunc = nullptr;

    VerifyOrReturnError(fuzz::Fuzzer::GetInstance() != nullptr, CHIP_FUZZER_ERROR_INITIALIZATION_FAILED);
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::RunCommand()
{
    CHIP_ERROR err               = InitializeFuzzer();
    const char * kExampleCommand = "onoff on ";
    VerifyOrReturnError(CHIP_NO_ERROR == err, err);
    // TODO: get dynamic node id from command line
    // Retrieve device configuration using Descriptor cluster and initialize the state
    VerifyOrReturnError(CHIP_NO_ERROR == RetrieveNodeDescription(mDestinationId), CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    // VerifyOrReturnError(CHIP_NO_ERROR == SubscribeAll(0xB), CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    int status = 0;
    ExecuteCommand(std::string(kExampleCommand).append(std::to_string(mDestinationId)).append(" 1").c_str(), &status);
    // Get all cluster states for the node i at endpoint j
    // auto * clustersMap = mFuzzer->GetDeviceStateManager()->GetClustersOnEndpoint(0xB, 0);
    // VerifyOrReturnError(clustersMap != nullptr, CHIP_ERROR_INTERNAL);

    // // Run the fuzzer: execute mIterations commands for each cluster
    // for (uint32_t i = 0U; i < mIterations.Value(); i++)
    // {
    //     for (auto cluster : *clustersMap)
    //     {
    //         int status                = 0;
    //         chip::ClusterId clusterId = cluster.first;

    //         const char * command = GenerateCommand(clusterId); // cluster.first = cluster ID
    //         ExecuteCommand(command, &status);
    //         VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_UNEXPECTED_ERROR);
    //     }
    // }

    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};

const char * FuzzingStartCommand::GenerateCommand(chip::ClusterId cluster)
{
    fuzz::Fuzzer * fuzzer = fuzz::Fuzzer::GetInstance();
    VerifyOrReturnError(fuzzer != nullptr, nullptr);
    return fuzzer->GenerateCommand();
};
