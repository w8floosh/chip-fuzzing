#include "FuzzingCommands.h"
#include "DeviceStateManager.h"
#include "Oracle.h"
#include "Utils.h"
#include "Visitors.h"
#include "editline.h"
#include "generation/RuntimeGrammarManager.h"
#include <atomic>
#include <cstring>
#include <future>
#include <numeric>
#include <regex>
#include <string>
#include <thread>

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

// Removes duplicate keys from the JSON and converts all keys from hex to decimal.
std::string PreprocessGeneratedArgs(chip::NodeId node, std::string argsStr)
{
    Json::Value root;
    Json::CharReaderBuilder reader;
    std::string errs;

    std::string endpoint, cluster, command;
    std::istringstream iss(argsStr);

    // Skip the first three tokens (endpoint, cluster, command)
    iss >> endpoint >> cluster >> command;

    if (!Json::parseFromStream(reader, iss, &root, &errs))
    {
        std::cerr << "Error parsing JSON: " << errs << std::endl;
        return "";
    }

    // Serialize back to string without duplicate keys
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";
    std::string json      = Json::writeString(writer, root);
    std::string payload   = convertHexToDecimal(json);

    return cluster + " " + command + " " + payload + " " + std::to_string(node) + " " + endpoint;
}

void AddDefaultValueToPayload(Json::Value & payload, std::string id, chip::TLV::TLVType type, uint8_t size)
{
    auto defaultValueGenerator = chip::fuzzing::utils::DefaultValuesGenerator::GetInstance();
    switch (type)
    {
    case chip::TLV::TLVType::kTLVType_List:
    case chip::TLV::TLVType::kTLVType_Array: {
        payload[id] = Json::Value(Json::arrayValue);
        break;
    }
    case chip::TLV::TLVType::kTLVType_Structure: {
        payload[id] = Json::Value(Json::objectValue);
        break;
    }
    case chip::TLV::TLVType::kTLVType_Null: {
        payload[id] = Json::Value(Json::nullValue);
        break;
    }
    case chip::TLV::TLVType::kTLVType_Boolean: {
        payload[id] = false;
        break;
    }
    default: {
        payload[id] = defaultValueGenerator.GetDefaultValue({ type, size });
        break;
    }
    }
}
} // namespace

void FuzzingCommand::ExecuteCommand(const char * command, CHIP_ERROR * status)
{
    CHIP_ERROR contextError = CHIP_NO_ERROR;
    *status                 = mHandler->RunFuzzing(command);

    VerifyOrReturn(CHIP_ERROR_INVALID_ARGUMENT != *status,
                   ChipLogError(chipFuzzer, "Could not parse command string correctly. Test case was skipped."));

    auto contextManager = fuzz::Fuzzer::GetInstance()->GetContextManager();
    contextError        = contextManager->Finalize();
    if (CHIP_NO_ERROR != contextError)
    {
        ChipLogError(chipFuzzer, "Context finalization failure: %s", chip::ErrorStr(contextError));
    }
    contextError = contextManager->Close();
    if (CHIP_NO_ERROR != contextError || contextManager->IsInitialized())
    {
        ChipLogError(chipFuzzer, "Could not terminate current fuzzer context gracefully. Forcing close.");
        VerifyOrDie(CHIP_NO_ERROR == contextManager->Close(true));
    }
}

bool FuzzingStartCommand::TestTCPServerSupport()
{
    auto fuzzer             = fuzz::Fuzzer::GetInstance();
    auto deviceStateManager = fuzzer->GetDeviceStateManager();

    CHIP_ERROR err = CHIP_NO_ERROR;
    VerifyOrDie(deviceStateManager->List(mDestinationId) && !!(deviceStateManager->List(mDestinationId)->size()));
    for (auto & [endpointId, _] : *deviceStateManager->List(mDestinationId))
    {
        VerifyOrDie(deviceStateManager->List(mDestinationId, endpointId) &&
                    !!(deviceStateManager->List(mDestinationId, endpointId)->size()));
        for (auto & [clusterId, _] : *deviceStateManager->List(mDestinationId, endpointId))
        {
            auto commandList = deviceStateManager->ReadAttribute(mDestinationId, endpointId, clusterId,
                                                                 chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id);
            if (std::holds_alternative<std::monostate>(commandList))
            {
                continue;
            }

            auto firstCommand      = std::get<fuzz::ContainerType>(commandList).front();
            auto commandId         = chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(firstCommand);
            std::string commandStr = "any command-by-id " + std::to_string(clusterId) + " " + std::to_string(commandId) + " {} " +
                std::to_string(mDestinationId) + " " + std::to_string(endpointId) + " --allow-large-payload true";

            ExecuteCommand(commandStr.c_str(), &err);
            fuzzer->AppendToHistory(commandStr.c_str(), err);
            return err != CHIP_ERROR_INTERNAL;
        }
    }
    return false;
}

CHIP_ERROR FuzzingStartCommand::AcquireBasicInformation()
{
    CHIP_ERROR status          = CHIP_NO_ERROR;
    std::ostringstream command = std::ostringstream() << "basicinformation read data-model-revision " << mDestinationId << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read vendor-name " << mDestinationId << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read vendor-id " << mDestinationId << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read product-id " << mDestinationId << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read hardware-version " << mDestinationId << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    command = std::ostringstream() << "basicinformation read software-version " << mDestinationId << " 0";
    ExecuteCommand(command.str().c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::DeduceExpectedErrors(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command,
                                                     std::unordered_set<IMStatus> & errors,
                                                     chip::Optional<fs::path> dependencyTestFile)
{
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";
    std::map<uint8_t, const std::pair<chip::TLV::TLVType, uint8_t>> commandFields;
    const std::string baseCommandStr = "any command-by-id " + std::to_string(cluster) + " " + std::to_string(command) + " ";
    auto fuzzer                      = fuzz::Fuzzer::GetInstance();

    // TODO
    if (dependencyTestFile.HasValue())
    {
        ChipLogProgress(chipFuzzer, "Scrambling state of cluster (%d, %d) to test dependencies of the command %d...", endpoint,
                        cluster, command);
        std::ifstream file(dependencyTestFile.Value());
        // The tmp file is used to write the lines that do not match commands belonging to the same cluster of the command in
        // analysis, or match an instance of the command itself.
        std::ofstream tmp(dependencyTestFile.Value().parent_path() / "tmp.txt");
        std::unordered_map<chip::CommandId, std::vector<std::string>> clusterTestcasesMap;
        CHIP_ERROR subCommandErr;
        std::string generatedArgs;
        // This loop consumes the generated test cases from the file and organizes the resulting commands inside a map if they
        // belong to the same cluster than the command that is being analyzed.
        while (std::getline(file, generatedArgs))
        {
            std::string subcommand = "any command-by-id ";
            std::string scArgs     = PreprocessGeneratedArgs(mDestinationId, generatedArgs);
            std::istringstream iss(scArgs);
            std::string scNode, scEndpoint, scCluster, scCommand, scPayload;
            iss >> scCluster >> scCommand >> scPayload >> scNode >> scEndpoint;
            if (scEndpoint != std::to_string(endpoint) || scCluster != std::to_string(cluster) ||
                (scEndpoint == std::to_string(endpoint) && scCluster == std::to_string(cluster) &&
                 scCommand == std::to_string(command)))
            {
                tmp << (subcommand + scArgs) << std::endl;
                continue;
            }

            clusterTestcasesMap[std::stoi(scCommand)].push_back(subcommand + scArgs);
        }

        // Swap the temporary file with the dependency testcases file
        VerifyOrDie(fs::remove(dependencyTestFile.Value().c_str()));
        fs::rename(dependencyTestFile.Value().parent_path() / "tmp.txt", dependencyTestFile.Value().c_str());

        // This loop iterates over the map and executes all the commands to scramble the device state. This may be useful because
        // certain dependencies are met only when the device is in a particular state, hence showing unusual errors.
        for (auto [cid, subcommands] : clusterTestcasesMap)
        {
            for (auto & subcommand : subcommands)
            {
                ExecuteCommand(subcommand.c_str(), &subCommandErr);
                // TODO: Find a way to separate commands executed in the exploration phase and the ones executed in the testing
                // phase.
                fuzzer->AppendToHistory(subcommand.c_str(), subCommandErr);
                VerifyOrReturnError(subCommandErr != CHIP_ERROR_TIMEOUT, CHIP_ERROR_TIMEOUT);
            }
        }
    }

    Json::Value basePayload = Json::Value(Json::objectValue);

    /**
     * Main loop for discovering command fields required by the command. Command fields are always ascending consecutive
     * context-tags and, ideally, should be less than 16 per command.
     * You don't want to have more than 16 fields in a command, don't you?
     */
    for (int id = 0; id < 16; id++)
    {
        for (auto [type, size] : fuzz::supportedTypes)
        {
            bool currentTypeIsString =
                type == chip::TLV::TLVType::kTLVType_UTF8String || type == chip::TLV::TLVType::kTLVType_ByteString;

            if ((size > 4 && currentTypeIsString) || (size > 2 && currentTypeIsString && !mDestinationSupportsTCPServer))
                continue;

            Json::Value currentPayload(basePayload);
            CHIP_ERROR err;
            std::string commandStr(baseCommandStr);
            AddDefaultValueToPayload(currentPayload, std::to_string(id), type, size);

            std::string json = Json::writeString(writer, currentPayload);
            commandStr += json + " " + std::to_string(mDestinationId) + " " + std::to_string(endpoint);

            if (mDestinationSupportsTCPServer)
            {
                commandStr += " --allow-large-payload true";
            }

            ExecuteCommand(commandStr.c_str(), &err);
            fuzzer->AppendToHistory(commandStr.c_str(), err);
            // If this is false, we found a required field for which the device returns an error if the field is malformed.
            if (err == CHIP_NO_ERROR)
                continue;

            chip::app::StatusIB statusResponse(err);
            if (statusResponse.mStatus == IMStatus::InvalidCommand)
            {
                continue;
            }
            commandFields.emplace(static_cast<uint8_t>(id), std::make_pair(type, size));
            errors.emplace(statusResponse.mStatus);
            AddDefaultValueToPayload(basePayload, std::to_string(id), type, size);
            break;
        }
    }
    // errors = [SUCCESS]
    // commandFields = ordered_map<uint8, type>) ()
    // for field in [0x0...0xFF]:
    //   isField = false
    //   fieldType = not specified
    //   for type in ([u]int8/16/32/64, bool, char*8/16/32/64, string8/16/32/64):
    //     if type is convertible to string or char*:
    //       statusResponse = sendCommand(commandFields + field, [correctValuesForOtherFields..., generatedString[type_MAX_LEN])
    //     else
    //       statusResponse = sendCommand(commandFields + field, [correctValuesForOtherFields..., type_MAX_VALUE])
    //     if statusResponse != SUCCESS and not isField:
    //       isField = true
    //     if statusResponse == INVALID_COMMAND:
    //       continue
    //     statusResponse = sendCommand(commandFields + field, [correctValuesForOtherFields..., generatedPlausibleValue])
    //     errors.add(statusResponse)
    //     fieldType = type
    //     commandFields.add(field, type)
    //     break
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::AddOracleRules(chip::Optional<fs::path> dependencyTestFile)
{
    auto fuzzer                            = fuzz::Fuzzer::GetInstance();
    fuzz::DeviceStateManager * deviceState = fuzzer->GetDeviceStateManager();
    fuzz::Oracle * oracle                  = fuzzer->GetOracle();
    for (auto & endpoint : *deviceState->List(mDestinationId))
    {
        for (auto & cluster : *deviceState->List(mDestinationId, endpoint.first))
        {
            auto acceptedCommandList = std::get<fuzz::ContainerType>(deviceState->ReadAttribute(
                mDestinationId, endpoint.first, cluster.first, chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id));
            for (auto & command : acceptedCommandList)
            {
                auto commandId = chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(command);
                std::unordered_set<IMStatus> errors({ IMStatus::Success });
                DeduceExpectedErrors(endpoint.first, cluster.first, commandId, errors, dependencyTestFile);
                oracle->AddRule(endpoint.first, cluster.first, commandId, std::move(errors));
            }
        }
    }
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
FuzzingStartCommand::AcquireRemoteDataModel()
{
    // Access to the device state manager is required to add the new node and list the endpoints.
    auto fuzzer                            = fuzz::Fuzzer::GetInstance();
    fuzz::DeviceStateManager * deviceState = fuzzer->GetDeviceStateManager();
    CHIP_ERROR status                      = CHIP_NO_ERROR;
    deviceState->Add(mDestinationId);

    /**
     * Steps:
     * 1) get the endpoints of the node;
     * 2) for each endpoint, get the device type and server clusters (those who respond to commands);
     * 3) for each cluster, read all attributes and events and subscribe to them.
     *
     * The command response callbacks will parse the response and update the device state accordingly.
     */
    std::string retrieveEndpointsCommand = GetRetrieveEndpointsCommand(mDestinationId);

    ExecuteCommand(retrieveEndpointsCommand.c_str(), &status);
    VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    VerifyOrReturnError(deviceState->List(mDestinationId) != nullptr, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    for (auto & [endpointId, _] : *deviceState->List(mDestinationId))
    {
        std::string retrieveDeviceTypeCommand     = GetRetrieveDeviceTypeCommand(mDestinationId, endpointId);
        std::string retrieveServerClustersCommand = GetRetrieveServerClustersCommand(mDestinationId, endpointId);
        ExecuteCommand(retrieveDeviceTypeCommand.c_str(), &status);
        VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        ExecuteCommand(retrieveServerClustersCommand.c_str(), &status);
        VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        VerifyOrReturnError(deviceState->List(mDestinationId, endpointId) != nullptr, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

        for (auto & [clusterId, _] : *deviceState->List(mDestinationId, endpointId))
        {
            std::string readAllClusterAttributesCommand = GetReadAllClusterAttributesCommand(mDestinationId, endpointId, clusterId);

            // TODO: Retrieval of initial value is already done by the subscribe command. We should remove the read command.
            ExecuteCommand(readAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
        }
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::SubscribeAttributesAndEvents()
{
    auto deviceState  = fuzz::Fuzzer::GetInstance()->GetDeviceStateManager();
    CHIP_ERROR status = CHIP_NO_ERROR;

    for (auto & endpoint : *deviceState->List(mDestinationId))
    {
        for (auto & cluster : *deviceState->List(mDestinationId, endpoint.first))
        {
            std::string subscribeAllClusterAttributesCommand =
                GetSubscribeAllClusterAttributesCommand(mDestinationId, endpoint.first, cluster.first);

            // TODO: Retrieval of initial value is already done by the subscribe command. We should remove the read command.
            ExecuteCommand(subscribeAllClusterAttributesCommand.c_str(), &status);
            VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            VerifyOrReturnError(deviceState->List(mDestinationId, endpoint.first, cluster.first) != nullptr,
                                CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);

            auto eventList = deviceState->ReadAttribute(mDestinationId, endpoint.first, cluster.first,
                                                        chip::app::Clusters::Globals::Attributes::EventList::Id);
            if (!std::holds_alternative<chip::fuzzing::ContainerType>(eventList))
                continue;

            for (auto & event : std::get<chip::fuzzing::ContainerType>(eventList))
            {
                std::string subscribeClusterEventCommand = GetSubscribeEventCommand(
                    mDestinationId, endpoint.first, cluster.first, chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(event));

                ExecuteCommand(subscribeClusterEventCommand.c_str(), &status);
                VerifyOrReturnError(status == CHIP_NO_ERROR, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
            }
        }
    }
    return CHIP_NO_ERROR;
}
CHIP_ERROR FuzzingStartCommand::InitializeFuzzer()
{
    if (!fs::exists(fs::path(mOutputDirectoryArgument)))
    {
        fs::create_directories(mOutputDirectoryArgument);
    }
    mOutputDirectory.SetValue(fs::path(mOutputDirectoryArgument));
    fuzz::Fuzzer::Initialize(mDestinationId, mOutputDirectory.Value());

    VerifyOrReturnError(fuzz::Fuzzer::GetInstance() != nullptr, CHIP_FUZZER_ERROR_CORE_INITIALIZATION_FAILED);
    return CHIP_NO_ERROR;
}

CHIP_ERROR FuzzingStartCommand::RunCommand()
{
    ReturnErrorOnFailure(InitializeFuzzer());

    fs::path generatedGrammarsDirectory = mOutputDirectory.Value() / "grammars";
    CHIP_ERROR status                   = CHIP_NO_ERROR;
    CHIP_ERROR finalStatus              = CHIP_NO_ERROR;
    auto fuzzer                         = fuzz::Fuzzer::GetInstance();
    auto deviceStateManager             = fuzzer->GetDeviceStateManager();

    fuzzer->GoToNextPhase();

    ReturnErrorOnFailure(AcquireRemoteDataModel());

    auto * endpointList = deviceStateManager->List(mDestinationId);
    VerifyOrReturnError(endpointList, CHIP_FUZZER_ERROR_NODE_SCAN_FAILED);
    ReturnErrorOnFailure(AcquireBasicInformation());

    mDestinationSupportsTCPServer = TestTCPServerSupport();

    const fuzz::BasicInformation * nodeInfo = deviceStateManager->GetNodeInformation(mDestinationId);

    fuzz::generation::RuntimeGrammarManager grammarManager(nodeInfo, generatedGrammarsDirectory.string());
    grammarManager.CreateGrammar(deviceStateManager, mDestinationId);
    fs::path testcasesFile = generatedGrammarsDirectory / grammarManager.mGrammarId / "tests.txt";
    if (!fs::exists(testcasesFile))
    {
        grammarManager.GenerateTestCases(testcasesFile, mTests, 18);
    }

    fs::path dependencyTestcasesFile = generatedGrammarsDirectory / grammarManager.mGrammarId / "dependency_tests.txt";
    grammarManager.GenerateTestCases(dependencyTestcasesFile, deviceStateManager->GetTotalCommands() * 16, 18);
    fuzzer->GoToNextPhase();

    ReturnErrorOnFailure(AddOracleRules(chip::Optional<fs::path>::Value(dependencyTestcasesFile)));
    fuzzer->GoToNextPhase();

    std::ifstream file(testcasesFile);
    /**
     * Strings generated by Grammarinator come with the form ENDPOINT CLUSTER COMMAND JSON.
     * To fit the generated content into a command, we must preprocess it to fit the syntax "any command-by-id CLUSTER
     * COMMAND JSON NODE ENDPOINT" as required by the chip-tool parser. Also, the JSON must be preprocessed to convert hex
     * values to decimal and to remove duplicate keys.
     */
    std::string generatedArgs;

    // std::atomic<uint32_t> testIndex(1);
    const auto startTime = std::chrono::steady_clock::now();
    // std::atomic<bool> running(true);
    // auto statusPrintFuture = std::async(std::launch::async, fuzz::PrintStatusLine, std::ref(running), startTime,
    //                                     std::ref(testIndex), mTests.Value(), status,
    //                                     fuzzer->mOracle->GetCurrentStatus());

    while (std::getline(file, generatedArgs))
    {
        // fuzz::PrintStatusLine(startTime, testIndex, mTests.Value(), status, fuzzer->mOracle->GetCurrentStatus());
        std::string command = "any command-by-id ";
        command += PreprocessGeneratedArgs(mDestinationId, generatedArgs);

        ExecuteCommand(command.c_str(), &status);
        fuzzer->AppendToHistory(command.c_str(), status);

        if (fuzzer->GetOracle()->GetCurrentStatus() == fuzz::OracleStatus::UNREACHABLE)
        {
            ChipLogError(chipFuzzer, "The node is unreachable or may have crashed.");
            finalStatus = CHIP_ERROR_UNEXPECTED_EVENT;
        }
        // ++testIndex;
    }
    // running = false;
    // statusPrintFuture.wait();

    // Clear the terminal
    std::cout << "\033[2J\033[1;1H";

    if (finalStatus == CHIP_NO_ERROR)
    {
        ChipLogProgress(chipFuzzer, "Fuzzing completed in %s.", fuzz::GetElapsedTime(startTime).c_str());
    }
    else
    {
        ChipLogError(chipFuzzer, "The fuzzer lost connection with the device. Please check the command history logs.");
    }

    fuzzer->GetDeviceStateManager()->Dump(fuzzer->mCommandHistory);
    ChipLogProgress(chipFuzzer, "The device state and command history were dumped in the statedumps folder.");

    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};
