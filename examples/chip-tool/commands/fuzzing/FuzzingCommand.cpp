#include "FuzzingCommand.h"
#include <numeric>
#include <string>

namespace {
inline constexpr char kRetrieveDeviceTypeCommand[] =
    "descriptor read device-type-list "; // returns device type for each endpoint of the node
inline constexpr char kRetrievePartsCommand[]          = "descriptor read parts-list ";  // returns endpoints of the node
inline constexpr char kRetrieveServerClustersCommand[] = "descriptor read server-list "; // returns clusters of all endpoints
void split(const std::string & s, char delim, const char ** output)
{
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim))
    {
        *output++ = item.c_str();
    }
}
} // namespace

namespace fuzz = chip::fuzzing;

CHIP_ERROR
FuzzingCommand::RetrieveNodeDescription(NodeId id, fuzz::NodeDataRaw * const & description)
{

    int * status;
    std::any nodeData;
    std::string command;
    const int argc = 5;
    char ** argv   = new char *[argc];

    *description            = new fuzz::NodeDataRaw();
    std::string commandType = kRetrievePartsCommand;
    command                 = commandType.append(std::to_string(id)).append(" 0xffff");
    split(command, ' ', argv);
    *status = mHandler->Run(argc, argv); // this needs to return command output

    commandType = kRetrieveDeviceTypeCommand;
    command     = commandType.append(std::to_string(id).append(" 0xffff"));
    split(command, ' ', argv);
    *status = mHandler->Run(argc, argv); // this needs to return command output

    commandType = kRetrieveServerClustersCommand;
    command     = commandType.append(std::to_string(id).append(" 0xffff"));
    split(command, ' ', argv);
    *status = mHandler->Run(argc, argv); // this needs to return command output

    // populate NodeState object with obtained data

    return CHIP_NO_ERROR;
} // namespace chip::fuzzing
CHIP_ERROR FuzzingCommand::RunCommand()
{
    fuzz::NodeDataRaw * nodeDataRaw;

    // Retrieve device configuration using Descriptor cluster
    RetrieveNodeDescription(0, nodeDataRaw);
    mFuzzer->InitNodeState(0, nodeDataRaw);
    free(nodeDataRaw);
    nodeDataRaw = nullptr;

    return CHIP_ERROR_NOT_IMPLEMENTED;
};

char * GenerateCommand(chip::ClusterId cluster)
{
    char * command;
    return command;
};
