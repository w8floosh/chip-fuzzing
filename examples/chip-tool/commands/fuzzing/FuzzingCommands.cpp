#include "FuzzingCommands.h"
#include "DeviceStateManager.h"
#include "Utils.h"
#include "Visitors.h"
#include "editline.h"
#include "generation/RuntimeGrammarManager.h"
#include <cstring>
#include <numeric>
#include <regex>
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

void ReorderCommandArgs(std::ostringstream & commandArgs)
{
    std::istringstream iss(commandArgs.str());
    std::vector<std::string> tokens;
    std::string arg;
    while (iss >> arg)
    {
        tokens.push_back(arg);
    }
    std::rotate(tokens.begin(), tokens.begin() + 2, tokens.end());

    commandArgs.str("");
    commandArgs.clear();
    for (const auto & t : tokens)
    {
        commandArgs << t << " ";
    }
}

uint64_t hexToUnsignedInt(const std::string & hexStr)
{
    uint64_t value;
    std::stringstream ss;
    ss << std::hex << hexStr;
    ss >> value;
    return value;
}

// Convert hex string to signed integer
int64_t hexToSignedInt(const std::string & hexStr)
{
    uint64_t unsignedValue = hexToUnsignedInt(hexStr);
    // Interpret the value as a signed integer based on its length
    int64_t signedValue = static_cast<int64_t>(unsignedValue);
    return signedValue;
}

// Convert hex string to float
float hexToFloat(const std::string & hexStr)
{
    uint32_t intValue = static_cast<uint32_t>(hexToUnsignedInt(hexStr));
    float floatValue;
    std::memcpy(&floatValue, &intValue, sizeof(floatValue)); // Bitwise conversion
    return floatValue;
}

// Convert hex string to double
double hexToDouble(const std::string & hexStr)
{
    uint64_t intValue = hexToUnsignedInt(hexStr);
    double doubleValue;
    std::memcpy(&doubleValue, &intValue, sizeof(doubleValue)); // Bitwise conversion
    return doubleValue;
}

// Function to scan and convert hex values in JSON string
std::string convertHexToDecimal(std::string json)
{
    // Define the regular expression pattern for matching the values
    std::regex pattern(R"(\"(s:|f:|d:)?(0x[0-9a-fA-F]+)\")");
    std::smatch match;

    std::string result;
    std::string::const_iterator searchStart(json.cbegin());

    while (std::regex_search(searchStart, json.cend(), match, pattern))
    {
        // Append the part of the JSON before the match
        result += match.prefix();

        // Extract the matched components
        std::string prefix   = match[1]; // "s:", "f:", "d:", or empty
        std::string hexValue = match[2]; // Hex number

        // Remove "0x" prefix from the hex number for easier conversion
        hexValue = hexValue.substr(2);

        // Convert based on the prefix
        std::ostringstream convertedValue;
        convertedValue << prefix;
        if (prefix == "s:")
        {
            convertedValue << hexToSignedInt(hexValue) << "\"";
        }
        else if (prefix == "f:")
        {
            convertedValue << std::fixed << hexToFloat(hexValue) << std::dec << "\"";
        }
        else if (prefix == "d:")
        {
            convertedValue << std::fixed << hexToDouble(hexValue) << std::dec << "\"";
        }
        else
        {
            convertedValue << hexToUnsignedInt(hexValue) << "\"";
        }

        // Append the converted value to the result
        result += "\"" + convertedValue.str();

        // Move searchStart forward to continue searching the rest of the string
        searchStart = match.suffix().first;
    }

    // Append the remaining part of the JSON string
    result += std::string(searchStart, json.cend());

    return result;
}
} // namespace

void FuzzingCommand::ExecuteCommand(const char * command, int * status)
{
    *status = mHandler->RunFuzzing(command);
}

CHIP_ERROR FuzzingStartCommand::AcquireBasicInformation(NodeId nodeId, int * status)
{
    // uint16_t dmRevision;
    // std::string vendorName;
    // VendorId vendorId;
    // std::string productName;
    // ProductId productId;
    // uint16_t hwVersion;
    std::ostringstream command = std::ostringstream() << "basicinformation read data-model-revision " << nodeId << " 0";
    ExecuteCommand(command.str().c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read vendor-name " << nodeId << " 0";
    ExecuteCommand(command.str().c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read vendor-id " << nodeId << " 0";
    ExecuteCommand(command.str().c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read product-id " << nodeId << " 0";
    ExecuteCommand(command.str().c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read hardware-version " << nodeId << " 0";
    ExecuteCommand(command.str().c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read software-version " << nodeId << " 0";
    ExecuteCommand(command.str().c_str(), status);
    VerifyOrReturnError(*status == EXIT_SUCCESS, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    return CHIP_NO_ERROR;
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
    VerifyOrReturnError(CHIP_NO_ERROR == AcquireRemoteDataModel(mDestinationId), CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    auto fuzzer             = fuzz::Fuzzer::GetInstance();
    auto deviceStateManager = fuzzer->GetDeviceStateManager();
    int status              = 0;

    // Read the first line of each file in "out/testcases" and send it as a command
    auto * endpointList = deviceStateManager->List(mDestinationId);
    VerifyOrReturnError(endpointList && CHIP_NO_ERROR == AcquireBasicInformation(mDestinationId, &status),
                        CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    std::string testcasesDirectory          = "out/testcases";
    std::string generatedGrammarsDirectory  = "out/debug/standalone/chip-fuzzer-grammars";
    const fuzz::BasicInformation * nodeInfo = deviceStateManager->GetNodeInformation(mDestinationId);
    fuzz::generation::RuntimeGrammarManager grammarManager(nodeInfo, generatedGrammarsDirectory);
    grammarManager.CreateGrammar(deviceStateManager, mDestinationId);
    grammarManager.GenerateTestCases(testcasesDirectory, mIterations.Value());

    fs::directory_iterator endIterator;
    for (fs::directory_iterator iter(testcasesDirectory); iter != endIterator; ++iter)
    {
        if (fs::is_regular_file(iter->status()))
        {
            std::ifstream file(iter->path());
            if (file.is_open())
            {
                /**
                 * Strings generated by Grammarinator come with the form ENDPOINT CLUSTER COMMAND JSON.
                 * To fit the generated content into a command, we must append it to the command-by-id begin string and the node ID,
                 * then rotate the tokens of the string by 2 positions to match the desired format by the chip-tool.
                 * any command-by-id
                 */
                std::string generatedArgs;
                std::getline(file, generatedArgs);
                file.close();

                std::ostringstream command;
                std::ostringstream commandArgs;

                commandArgs << mDestinationId << " " << convertHexToDecimal(generatedArgs);
                ReorderCommandArgs(commandArgs);

                std::string reorderedCommandArgs = commandArgs.str();
                reorderedCommandArgs.pop_back(); // Remove the last space
                command << "any command-by-id " << reorderedCommandArgs;

                ExecuteCommand(command.str().c_str(), &status);
                fuzzer->AppendToHistory(command.str().c_str());
                // Handle the status as needed
            }
        }
    }

    fuzzer->GetDeviceStateManager()->Dump(fuzzer->mCommandHistory);

    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};

const char * FuzzingStartCommand::GenerateCommand(chip::ClusterId cluster)
{
    fuzz::Fuzzer * fuzzer = fuzz::Fuzzer::GetInstance();
    VerifyOrReturnError(fuzzer != nullptr, nullptr);
    return fuzzer->GenerateCommand();
};
