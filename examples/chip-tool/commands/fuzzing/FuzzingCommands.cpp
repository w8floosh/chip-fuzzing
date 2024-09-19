#include "FuzzingCommands.h"
#include <numeric>
#include <string>

namespace fuzz = chip::fuzzing;
namespace fs   = std::filesystem;
namespace {
inline std::string GetRetrieveEndpointsCommand(chip::NodeId node)
{
    std::string kCommand("descriptor read parts-list ");
    kCommand.append(std::to_string(node)).append(" 0");
    return kCommand;
}; // returns endpoints of the node
inline std::string GetRetrieveDeviceTypeCommand(chip::NodeId node, chip::EndpointId endpoint)
{
    std::string kCommand("descriptor read device-type-list "); // returns device type for each endpoint of the node
    kCommand.append(std::to_string(node)).append(" ").append(std::to_string(endpoint));
    return kCommand;
}; // returns device type of the endpoint
inline std::string GetRetrieveServerClustersCommand(chip::NodeId node, chip::EndpointId endpoint)
{
    std::string kCommand("descriptor read server-list ");
    kCommand.append(std::to_string(node)).append(" ").append(std::to_string(endpoint));
    return kCommand;
}; // returns clusters of all endpoints
inline std::string GetReadAllClusterAttributesCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    std::string kCommand("any read-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" 0xFFFFFFFF ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint));
    return kCommand;
}; // reads all attributes
inline std::string GetReadAllClusterEventsCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    std::string kCommand("any read-event-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" 0xFFFFFFFF ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint));
    return kCommand;
}; // reads all events
inline std::string GetSubscribeAllClusterAttributesCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    std::string kCommand("any subscribe-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" 0xFFFFFFFF")
        .append(" 0")
        .append(" -1")
        .append(std::to_string(endpoint))
        .append(" ")
        .append(std::to_string(cluster));
    return kCommand;
}; // subscribes to all attributes
inline std::string GetSubscribeAllClusterEventCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
{
    std::string kCommand("any subscribe-event-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" 0xFFFFFFFF")
        .append(" 0")
        .append(" -1")
        .append(std::to_string(endpoint))
        .append(" ")
        .append(std::to_string(cluster));
    return kCommand;
}; // subscribes to all events
} // namespace

void FuzzingCommand::ExecuteCommand(const char * command, int * status)
{
    *status = mHandler->RunFuzzing(command);
}

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
    // Access to the device state manager is required to add the new node and list the endpoints.
    fuzz::DeviceStateManager deviceState = fuzz::Fuzzer::GetInstance()->mDeviceStateManager;
    int status                           = 0;
    deviceState.Add(id);

    /**
     * Steps:
     * 1) get the endpoints of the node;
     * 2) for each endpoint, get the device type and server clusters (those who respond to commands);
     * 3) for each cluster, read all attributes and events and subscribe to them.
     *
     * The command response callbacks will parse the response and update the device state accordingly.
     */
    std::string retrieveEndpointsCommand = GetRetrieveEndpointsCommand(id);

    ExecuteCommand(retrieveEndpointsCommand.c_str(), &status);
    VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    for (auto & endpoint : deviceState.List(id))
    {
        std::string retrieveDeviceTypeCommand     = GetRetrieveDeviceTypeCommand(id, endpoint.first);
        std::string retrieveServerClustersCommand = GetRetrieveServerClustersCommand(id, endpoint.first);
        ExecuteCommand(retrieveDeviceTypeCommand.c_str(), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        ExecuteCommand(retrieveServerClustersCommand.c_str(), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        for (auto & cluster : deviceState.List(id, endpoint.first))
        {
            std::string readAllClusterAttributesCommand = GetReadAllClusterAttributesCommand(id, endpoint.first, cluster.first);
            std::string readAllClusterEventsCommand     = GetReadAllClusterEventsCommand(id, endpoint.first, cluster.first);

            ExecuteCommand(readAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            ExecuteCommand(readAllClusterEventsCommand.c_str(), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            std::string subscribeAllClusterAttributesCommand =
                GetSubscribeAllClusterAttributesCommand(id, endpoint.first, cluster.first);
            std::string subscribeAllClusterEventsCommand = GetSubscribeAllClusterEventCommand(id, endpoint.first, cluster.first);

            ExecuteCommand(subscribeAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            ExecuteCommand(subscribeAllClusterEventsCommand.c_str(), &status);
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
