#include "FuzzingCommands.h"
#include "DeviceStateManager.h"
#include "Oracle.h"
#include "Utils.h"
#include "Visitors.h"
#include "editline.h"
#include "generation/InputGenerator.h"
#include <algorithm>
#include <app/MessageDef/StatusIB.h>
#include <atomic>
#include <cstring>
#include <future>
#include <numeric>
#include <random>
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
} // namespace

void FuzzingCommand::ExecuteCommand(const char * command, CHIP_ERROR * status)
{
    CHIP_ERROR contextError = CHIP_NO_ERROR;
    auto fuzzer             = fuzz::Fuzzer::GetInstance();
    fuzzer->mCurrentCommand = command;
    *status                 = mHandler->RunFuzzing(command);

    VerifyOrReturn(CHIP_ERROR_INVALID_ARGUMENT != *status,
                   ChipLogError(chipFuzzer, "Could not parse command string correctly. Test case was skipped."));

    auto contextManager = fuzzer->GetContextManager();
    contextError        = contextManager->Finalize(fuzzer->CurrentPhase() == fuzz::FuzzerPhase::TESTING);
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
    if (fuzzer->mCurrentPhase != fuzz::FuzzerPhase::INITIALIZATION && fuzzer->mCurrentPhase != fuzz::FuzzerPhase::ACQUISITION)
        fuzzer->AppendToHistory(command, *status);
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

CHIP_ERROR FuzzingStartCommand::AddOracleRules(chip::Optional<fs::path> dependencyTestFile)
{
    auto fuzzer               = fuzz::Fuzzer::GetInstance();
    auto deviceState          = fuzzer->GetDeviceStateManager();
    auto oracle               = fuzzer->GetOracle();
    auto specificationEncoder = fuzzer->GetSpecificationEncoder();
    for (auto & [endpointId, _] : *deviceState->List(mDestinationId))
    {
        for (auto & [clusterId, _] : *deviceState->List(mDestinationId, endpointId))
        {
            auto acceptedCommandList = std::get<fuzz::ContainerType>(deviceState->ReadAttribute(
                mDestinationId, endpointId, clusterId, chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id));
            for (auto & command : acceptedCommandList)
            {
                auto commandId               = chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(command);
                fuzzer->mCurrentAnalyzedPath = chip::app::ConcreteCommandPath(endpointId, clusterId, commandId);
                ReturnErrorOnFailure(specificationEncoder->TryInferCommandSpecification(
                    endpointId, clusterId, commandId, dependencyTestFile.Value(), mDestinationSupportsTCPServer));
                oracle->AddRule(endpointId, clusterId, commandId,
                                specificationEncoder->GetExpectedErrors(fuzzer->mCurrentAnalyzedPath));
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
    fuzz::Fuzzer::Initialize(mDestinationId, mOutputDirectory.Value(), mTests, this);

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
    ReturnErrorOnFailure(SubscribeAttributesAndEvents());

    const fuzz::BasicInformation * nodeInfo = deviceStateManager->GetNodeInformation(mDestinationId);

    fuzz::generation::InputGenerator inputGenerator(nodeInfo, generatedGrammarsDirectory.string());
    inputGenerator.CreateGrammar(deviceStateManager, mDestinationId);
    fs::path testcasesFile = generatedGrammarsDirectory / inputGenerator.mGrammarId / "tmp" / "tests.txt";
    if (!fs::exists(testcasesFile))
    {
        inputGenerator.GenerateTestCases(testcasesFile, mTests, 18);
    }

    fs::path dependencyTestcasesFile = generatedGrammarsDirectory / inputGenerator.mGrammarId / "tmp" / "dependency_tests.txt";
    inputGenerator.GenerateTestCases(dependencyTestcasesFile, deviceStateManager->GetTotalCommands() * 16, 18);
    fuzzer->GoToNextPhase();

    ReturnErrorOnFailure(AddOracleRules(chip::Optional<fs::path>::Value(dependencyTestcasesFile)));
    VerifyOrDie(fs::remove(dependencyTestcasesFile.c_str()));
    fuzzer->GoToNextPhase();

    std::ifstream file(testcasesFile);
    /**
     * Strings generated by Grammarinator come with the form ENDPOINT CLUSTER COMMAND JSON.
     * To fit the generated content into a command, we must preprocess it to fit the syntax "any command-by-id CLUSTER
     * COMMAND JSON NODE ENDPOINT" as required by the chip-tool parser. Also, the JSON must be preprocessed to convert hex
     * values to decimal and to remove duplicate keys.
     */
    std::string generatedArgs;

    while (std::getline(file, generatedArgs))
    {
        std::string command = "any command-by-id ";
        command += fuzz::generation::InputGenerator::ParseTestCase(mDestinationId, generatedArgs);

        ExecuteCommand(command.c_str(), &status);

        if (fuzzer->mOracle.GetCurrentStatus() == fuzz::OracleStatus::UNREACHABLE)
        {
            ChipLogError(chipFuzzer, "The node is unreachable or may have crashed.");
            finalStatus = CHIP_ERROR_UNEXPECTED_EVENT;
            break;
        }
        fuzzer->mTestIndex++;
    }
    file.close();

    if (finalStatus == CHIP_NO_ERROR)
    {
        ChipLogProgress(chipFuzzer, "Fuzzing completed in %s. Dumping telemetry data...",
                        fuzz::GetElapsedTime(fuzzer->mStateMonitor.GetStartTime()).c_str());
    }
    else
    {
        ChipLogError(chipFuzzer, "The fuzzer lost connection with the device. Please check the command history logs.");
    }

    fuzzer->GetStateMonitor()->DumpTelemetry();
    deviceStateManager->Dump(fuzzer->mCommandHistory);
    ChipLogProgress(chipFuzzer, "Fuzzing telemetry and device state was dumped in the output folder.");
    ChipLogProgress(chipFuzzer, "Cleaning up data allocated by the fuzzer...");
    // fuzzer->Cleanup();

    SetCommandExitStatus(CHIP_NO_ERROR);
    return CHIP_NO_ERROR;
};
