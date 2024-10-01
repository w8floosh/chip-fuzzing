#include "FuzzingCommands.h"
#include "Utils.h"
#include "Visitors.h"
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
inline std::string GetReadClusterEventCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster)
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
        .append(" -1 ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint));
    return kCommand;
}; // subscribes to all attributes
inline std::string GetSubscribeEventCommand(chip::NodeId node, chip::EndpointId endpoint, chip::ClusterId cluster,
                                            chip::EventId event)
{
    std::string kCommand("any subscribe-event-by-id ");
    kCommand.append(std::to_string(cluster))
        .append(" ")
        .append(std::to_string(event))
        .append(" 0")
        .append(" -1 ")
        .append(std::to_string(node))
        .append(" ")
        .append(std::to_string(endpoint));
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
    fuzz::DeviceStateManager * deviceState = fuzz::Fuzzer::GetInstance()->GetDeviceStateManager();
    int status                             = 0;
    deviceState->Add(id);

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
    VerifyOrReturnError(deviceState->List(id) != nullptr, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    for (auto & endpoint : *deviceState->List(id))
    {
        std::string retrieveDeviceTypeCommand     = GetRetrieveDeviceTypeCommand(id, endpoint.first);
        std::string retrieveServerClustersCommand = GetRetrieveServerClustersCommand(id, endpoint.first);
        ExecuteCommand(retrieveDeviceTypeCommand.c_str(), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        ExecuteCommand(retrieveServerClustersCommand.c_str(), &status);
        VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        VerifyOrReturnError(deviceState->List(id, endpoint.first) != nullptr, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        for (auto & cluster : *deviceState->List(id, endpoint.first))
        {
            std::string readAllClusterAttributesCommand = GetReadAllClusterAttributesCommand(id, endpoint.first, cluster.first);
            std::string subscribeAllClusterAttributesCommand =
                GetSubscribeAllClusterAttributesCommand(id, endpoint.first, cluster.first);

            ExecuteCommand(readAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
            ExecuteCommand(subscribeAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            VerifyOrReturnError(deviceState->List(id, endpoint.first, cluster.first) != nullptr,
                                CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            auto eventList = deviceState->ReadAttribute(id, endpoint.first, cluster.first,
                                                        chip::app::Clusters::Globals::Attributes::EventList::Id);
            if (!std::holds_alternative<chip::fuzzing::ContainerType>(eventList))
                continue;

            for (auto & event : std::get<chip::fuzzing::ContainerType>(eventList))
            {
                std::string subscribeClusterEventCommand = GetSubscribeEventCommand(
                    id, endpoint.first, cluster.first, chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(event));

                ExecuteCommand(subscribeClusterEventCommand.c_str(), &status);
                VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
            }
        }
    }
    deviceState->Dump();
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
        fuzz::Fuzzer::Initialize(mDestinationId, mSeedDirectory, kGenerationFunc, fs::path("statedumps"), mOutputDirectory.Value());
    }
    else
    {
        fuzz::Fuzzer::Initialize(mDestinationId, mSeedDirectory, kGenerationFunc, fs::path("statedumps"));
    }

    kGenerationFunc = nullptr;

    VerifyOrReturnError(fuzz::Fuzzer::GetInstance() != nullptr, CHIP_FUZZER_ERROR_INITIALIZATION_FAILED);
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::RunCommand()
{
    CHIP_ERROR err = InitializeFuzzer();
    VerifyOrReturnError(CHIP_NO_ERROR == err, err);

    const char * kExampleCommandOn  = "onoff on ";
    const char * kExampleCommandOff = "onoff off ";
    VerifyOrReturnError(CHIP_NO_ERROR == AcquireRemoteDataModel(mDestinationId), CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    auto fuzzer = fuzz::Fuzzer::GetInstance();
    int status  = 0;

    for (int i = 0; i < 10; i++)
    {
        if (i % 2 == 0)
        {
            ExecuteCommand(std::string(kExampleCommandOn).append(std::to_string(mDestinationId)).append(" 1").c_str(), &status);
            fuzzer->AppendToHistory(std::string(kExampleCommandOn).append(std::to_string(mDestinationId)).append(" 1").c_str());
        }
        else
        {
            ExecuteCommand(std::string(kExampleCommandOff).append(std::to_string(mDestinationId)).append(" 1").c_str(), &status);
            fuzzer->AppendToHistory(std::string(kExampleCommandOff).append(std::to_string(mDestinationId)).append(" 1").c_str());
        }
    }

    fuzzer->GetDeviceStateManager()->Dump(fuzzer->mCommandHistory);
    // for (const auto & endpoint : fuzzer->GetDeviceStateManager()->List(mDestinationId))
    // {
    //     for (const auto & cluster : endpoint.second.clusters)
    //     {
    //         for (uint32_t i = 0; i < mIterations.Value(); i++)
    //         {
    //             // TODO: For each generated command, we should execute an extra read command to verify the new state of the
    //             // attribute.
    //             const char * command = GenerateCommand(cluster.first);
    //             ExecuteCommand(command, &status);
    //             VerifyOrReturnError(status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NOT_IMPLEMENTED);
    //         }
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
