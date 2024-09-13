#include "FuzzingCommands.h"
#include "DeviceStateManager.h"
#include <numeric>
#include <string>

namespace {
inline const char * GetRetrieveDeviceTypeCommand(chip::NodeId node, chip::EndpointId endpoint)
{
    const char * kCommand = "descriptor read device-type-list "; // returns device type for each endpoint of the node
    return std::string(kCommand).append(std::to_string(node)).append(" ").append(std::to_string(endpoint)).c_str();
};
inline const char * GetRetrieveEndpointsCommand(chip::NodeId node)
{
    const char * kCommand = "descriptor read parts-list ";
    return std::string(kCommand).append(std::to_string(node)).append(" 0xFFFF").c_str();
}; // returns endpoints of the node
inline const char * GetRetrieveServerClustersCommand(chip::NodeId node, chip::EndpointId endpoint)
{
    const char * kCommand = "descriptor read server-list ";
    return std::string(kCommand).append(std::to_string(node)).append(" ").append(std::to_string(endpoint)).c_str();
}; // returns clusters of all endpoints
inline const char * GetReadAllClusterAttributesCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    const char * kCommand = "any read-by-id ";
    return std::string(kCommand)
        .append(std::to_string(cluster))
        .append(" 0xFFFFFFFF ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint))
        .c_str();
}; // reads all attributes
inline const char * GetReadAllClusterEventsCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    const char * kCommand = "any read-event-by-id ";
    return std::string(kCommand)
        .append(std::to_string(cluster))
        .append(" 0xFFFFFFFF ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint))
        .c_str();
}; // reads all events
inline const char * GetSubscribeAllClusterAttributesCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    const char * kCommand = "any subscribe-by-id ";
    return std::string(kCommand)
        .append(std::to_string(cluster))
        .append(" 0xFFFFFFFF")
        .append(" 0")
        .append(" -1")
        .append(std::to_string(endpoint))
        .append(" ")
        .append(std::to_string(cluster))
        .c_str();
}; // subscribes to all attributes
inline const char * GetSubscribeAllClusterEventCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    const char * kCommand = "any subscribe-event-by-id ";
    return std::string(kCommand)
        .append(std::to_string(cluster))
        .append(" 0xFFFFFFFF")
        .append(" 0")
        .append(" -1")
        .append(std::to_string(endpoint))
        .append(" ")
        .append(std::to_string(cluster))
        .c_str();
}; // subscribes to all events
} // namespace

namespace fuzz = chip::fuzzing;

void FuzzingCommand::ExecuteCommand(const char * command, int * status)
{
    *status = mHandler->RunFuzzing(command);
}

/**
 *
 */
/**
 * Acquires the remote data model for a given NodeId.
 *
 * This method is responsible for acquiring the remote data model for a specific NodeId. It retrieves
 * the endpoints, device types, server clusters, and cluster attributes for the given NodeId. It also
 * subscribes to all cluster attributes and events for each endpoint and cluster. If any of the commands
 * fail to execute successfully, an error code is returned.
 *
 * @param id The NodeId for which to acquire the remote data model.
 * @return CHIP_NO_ERROR on success, or an error code indicating the reason for failure.
 */
CHIP_ERROR
FuzzingStartCommand::AcquireRemoteDataModel(NodeId id)
{
    int status = 0;
    ExecuteCommand(GetRetrieveEndpointsCommand(id), &status);
    VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    fuzz::DeviceStateManager deviceState = fuzz::Fuzzer::GetInstance()->mDeviceStateManager;
    for (auto & endpoint : deviceState.List(id))
    {
        ExecuteCommand(GetRetrieveDeviceTypeCommand(id, endpoint.first), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        ExecuteCommand(GetRetrieveServerClustersCommand(id, endpoint.first), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        for (auto & cluster : deviceState.List(id, endpoint.first))
        {
            ExecuteCommand(GetReadAllClusterAttributesCommand(id, endpoint.first, cluster.first), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            ExecuteCommand(GetSubscribeAllClusterAttributesCommand(id, endpoint.first, cluster.first), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            ExecuteCommand(GetSubscribeAllClusterEventCommand(id, endpoint.first, cluster.first), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        }
    }

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
    CHIP_ERROR err = InitializeFuzzer();
    VerifyOrReturnError(CHIP_NO_ERROR == err, err);

    const char * kExampleCommand = "onoff on ";
    VerifyOrReturnError(CHIP_NO_ERROR == AcquireRemoteDataModel(mDestinationId), CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    int status = 0;
    ExecuteCommand(std::string(kExampleCommand).append(std::to_string(mDestinationId)).append(" 1").c_str(), &status);
    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};

const char * FuzzingStartCommand::GenerateCommand(chip::ClusterId cluster)
{
    fuzz::Fuzzer * fuzzer = fuzz::Fuzzer::GetInstance();
    VerifyOrReturnError(fuzzer != nullptr, nullptr);
    return fuzzer->GenerateCommand();
};
