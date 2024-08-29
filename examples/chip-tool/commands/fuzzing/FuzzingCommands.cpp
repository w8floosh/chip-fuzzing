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

    int * status;
    std::string command;
    std::string commandType;

    // Get node endpoints
    commandType = kRetrievePartsCommand;
    command     = commandType.append(std::to_string(id)).append(" 0xffff");
    ExecuteCommand(command.c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_ERROR_INTERNAL);

    // Get device type for each endpoint
    commandType = kRetrieveDeviceTypeCommand;
    command     = commandType.append(std::to_string(id).append(" 0xffff"));
    ExecuteCommand(command.c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_ERROR_INTERNAL);

    // Return server clusters for each endpoint
    commandType = kRetrieveServerClustersCommand;
    command     = commandType.append(std::to_string(id).append(" 0xffff"));
    ExecuteCommand(command.c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_ERROR_INTERNAL);

    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::RunCommand()
{
    // TODO: get dynamic node id from command line
    // Retrieve device configuration using Descriptor cluster and initialize the state
    RetrieveNodeDescription(0);
    // Get all cluster states for the node i at endpoint j
    auto * clusterIterator = mFuzzer->GetDeviceStateManager()->GetEndpointClusters(0, 0);
    VerifyOrReturnError(clusterIterator != nullptr, CHIP_ERROR_INTERNAL);

    // Run the fuzzer: execute mIterations commands for each cluster
    for (int i = 0; i < mIterations; i++)
    {
        for (auto cluster : *clusterIterator)
        {
            int * status;
            const char * command = GenerateCommand(cluster.first); // cluster.first = cluster ID
            ExecuteCommand(command, status);
            VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_ERROR_INTERNAL);
        }
    }

    return CHIP_ERROR_NOT_IMPLEMENTED;
};

char * FuzzingStartCommand::GenerateCommand(chip::ClusterId cluster)
{
    char * command;
    return command;
};
