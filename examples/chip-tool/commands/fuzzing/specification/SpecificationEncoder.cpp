#include "SpecificationEncoder.h"
#include "../Fuzzer.h"
#include "../FuzzingCommands.h"
#include "../generation/InputGenerator.h"
#include <fstream>
#include <json/json.h>
#include <random>
namespace {
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

namespace spec = chip::fuzzing::specification;

// FIXME: Accurate command specification inference is unfeasible: it requires 16^(N*(N+1)/2) tests to be performed for a single
// command, where 16 is the number of types and N is the number of fields. A preliminary statistical analysis on the specification,
// to see how frequent is a type, may work better, but it is still a very expensive operation.

CHIP_ERROR spec::SpecificationEncoder::TryInferCommandSpecification(chip::EndpointId endpoint, chip::ClusterId cluster,
                                                                    chip::CommandId command, fs::path dependencyTestFile,
                                                                    bool enableTCP)
{
    Json::StreamWriterBuilder writer;
    writer["indentation"]            = "";
    const std::string baseCommandStr = "any command-by-id " + std::to_string(cluster) + " " + std::to_string(command) + " ";
    auto analyzedComPath             = chip::app::ConcreteCommandPath(endpoint, cluster, command);

    LogErrorOnFailure(ShuffleClusterState(dependencyTestFile, analyzedComPath));

    Json::Value basePayload = Json::Value(Json::objectValue);

    if (mCommandSpecifications.find(analyzedComPath) != mCommandSpecifications.end())
    {
        // Discovery would be useless. Specification already was inferred.
        return CHIP_NO_ERROR;
    }

    fs::path clusterCommandsFilePath =
        dependencyTestFile.parent_path() / (std::to_string(endpoint) + "_" + std::to_string(cluster) + "_commands.txt");

    std::ifstream clusterCommandsFile(clusterCommandsFilePath);
    std::string commandStr;
    // Execute all dependency tests associated with the command being analyzed.
    while (std::getline(clusterCommandsFile, commandStr))
    {
        CHIP_ERROR err;
        std::istringstream iss(commandStr);
        std::string scCommandSet, scOperation, scCluster, scCommand;
        iss >> scCommandSet >> scOperation >> scCluster >> scCommand;

        // Only the examples of the command in analysis are executed.
        if (scCommand != std::to_string(analyzedComPath.mCommandId))
            continue;

        mCommandHandler->ExecuteCommand(commandStr.c_str(), &err);
        mCommandSpecifications[analyzedComPath].inferredPossibleErrors.emplace(err);
        fuzz::Fuzzer::GetInstance()->GetStateMonitor()->TrackError(err);
    }

    return CHIP_NO_ERROR;

    // /**
    //  * Main loop for discovering command fields required by the command. Command fields are always ascending consecutive
    //  * context-tags and, ideally, should be less than 16 per command.
    //  * You don't want to have more than 16 fields in a command, don't you?
    //  */
    // for (int id = 0; id < 2; id++)
    // {
    //     bool isRequiredField = false;
    //     for (auto [type, size] : fuzz::supportedTypes)
    //     {
    //         bool currentTypeIsString =
    //             type == chip::TLV::TLVType::kTLVType_UTF8String || type == chip::TLV::TLVType::kTLVType_ByteString;

    //         if ((size > 4 && currentTypeIsString) || (size > 2 && currentTypeIsString && !enableTCP))
    //             continue;

    //         Json::Value currentPayload(basePayload);
    //         CHIP_ERROR err;
    //         std::string commandStr(baseCommandStr);
    //         AddDefaultValueToPayload(currentPayload, std::to_string(id), type, size);

    //         std::string json = Json::writeString(writer, currentPayload);
    //         commandStr += json + " " + std::to_string(mTarget) + " " + std::to_string(endpoint);

    //         if (enableTCP)
    //         {
    //             commandStr += " --allow-large-payload true";
    //         }

    //         mCommandHandler->ExecuteCommand(commandStr.c_str(), &err);
    //         // If this is false, we found a required field for which the device returns an error if the field is malformed.
    //         if (err == CHIP_NO_ERROR)
    //             continue;

    //         isRequiredField = true;
    //         chip::app::StatusIB statusResponse(err);
    //         if (statusResponse.mStatus == IMStatus::InvalidCommand)
    //             continue;

    //         mCommandSpecifications[analyzedComPath].requiredCommandFields.emplace(static_cast<uint8_t>(id),
    //                                                                               std::make_pair(type, size));
    //         mCommandSpecifications[analyzedComPath].inferredPossibleErrors.emplace(statusResponse.mStatus);
    //         AddDefaultValueToPayload(basePayload, std::to_string(id), type, size);
    //         break;
    //     }
    //     // We assume that the command fields start from ID 0 and are consecutive.
    //     // If sending the field with ID i never returns an error, it means it is ignored and it is obvious that all the IDs from
    //     // i to the last will be as well.
    //     if (!isRequiredField)
    //     {
    //         break;
    //     }
    // }
}
CHIP_ERROR spec::SpecificationEncoder::ShuffleClusterState(fs::path dependencyTestFilePath,
                                                           chip::app::ConcreteCommandPath analyzedComPath)
{
    ChipLogProgress(chipFuzzer, "Shuffling state of cluster (%d, %d) to test dependencies of the command %d...",
                    analyzedComPath.mEndpointId, analyzedComPath.mClusterId, analyzedComPath.mCommandId);
    int consecutiveTimeouts = 0;
    std::ifstream dependencyTestFile(dependencyTestFilePath);

    // The clusterCommands file is used to write the lines that do not match commands belonging to the same cluster of the
    // command in analysis, or match an instance of the command itself.
    fs::path clusterCommandsFilePath = dependencyTestFilePath.parent_path() /
        (std::to_string(analyzedComPath.mEndpointId) + "_" + std::to_string(analyzedComPath.mClusterId) + "_commands.txt");

    std::ofstream tmpFile(dependencyTestFilePath.parent_path() / "tmp_dependency_tests.txt");
    std::vector<std::string> clusterCommands;
    // If the file doesn't exist, test cases from this cluster are evicted from the dependency test corpus and transferred into a
    // new file.
    if (!fs::exists(clusterCommandsFilePath))
    {
        auto fuzzer = chip::fuzzing::Fuzzer::GetInstance();
        std::ofstream clusterCommandsFile(clusterCommandsFilePath);
        std::string generatedArgs;
        // This loop consumes the generated test cases from the file and organizes the resulting commands inside a map if they
        // belong to the same cluster than the command that is being analyzed.
        while (std::getline(dependencyTestFile, generatedArgs))
        {
            std::string subcommand = "any command-by-id ";
            std::string scArgs     = generation::InputGenerator::ParseTestCase(fuzzer->CurrentDestination(), generatedArgs);
            std::istringstream iss(scArgs);
            std::string scNode, scEndpoint, scCluster, scCommand, scPayload;
            iss >> scCluster >> scCommand >> scPayload >> scNode >> scEndpoint;
            if (scEndpoint != std::to_string(analyzedComPath.mEndpointId) ||
                scCluster != std::to_string(analyzedComPath.mClusterId))
            {
                // Ignores the line if it does not belong to the cluster of the command in analysis.
                tmpFile << generatedArgs << std::endl;
            }
            else
            {
                clusterCommandsFile << (subcommand + scArgs) << std::endl;
                if (scCommand != std::to_string(analyzedComPath.mCommandId))
                {
                    clusterCommands.push_back(subcommand + scArgs);
                }
            }
        }

        // Replace the original file with the new one with the evicted lines (speeds up the process for next clusters).
        VerifyOrDie(fs::remove(dependencyTestFilePath.c_str()));
        fs::rename(dependencyTestFilePath.parent_path() / "tmp_dependency_tests.txt", dependencyTestFilePath.c_str());
    }
    // In this case the file is already created and test cases are just added to the map.
    else
    {
        std::string subcommand;
        std::ifstream clusterCommandsFile(clusterCommandsFilePath);
        while (std::getline(clusterCommandsFile, subcommand))
        {
            clusterCommands.push_back(subcommand);
        }
    }

    // Shuffles the test cases list. When tests from the same file are requested multiple times, the same tests are shuffled each
    // time, modifying the sequence of commands executed.
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(clusterCommands.begin(), clusterCommands.end(), g);

    CHIP_ERROR subCommandErr;
    // This loop iterates over the map and executes all the commands to shuffle the cluster state. This may be useful because
    // certain dependencies are met only when the device is in a particular state, hence showing unusual errors.
    for (auto subcommand : clusterCommands)
    {
        std::istringstream iss(subcommand);
        std::string scCommandSet, scOperation, scCluster, scCommand, scPayload, scNode, scEndpoint;
        iss >> scCommandSet >> scOperation >> scCluster >> scCommand >> scPayload >> scNode >> scEndpoint;

        // The command in analysis is not executed.
        if (scCommand == std::to_string(analyzedComPath.mCommandId))
            continue;

        auto subCommandPath = chip::app::ConcreteCommandPath(std::stoul(scEndpoint), std::stoul(scCluster), std::stoul(scCommand));

        // If the specification of the subcommand was already inferred and it requires one or more fields, execute the command
        // twice: one with a payload containing the required fields with default values and one with the randomly generated payload
        // by Grammarinator.
        if (mCommandSpecifications.find(subCommandPath) != mCommandSpecifications.end() &&
            !mCommandSpecifications[subCommandPath].requiredCommandFields.empty())
        {
            Json::Value payloadWithDefaults = Json::Value(Json::objectValue);
            Json::StreamWriterBuilder writer;
            writer["indentation"] = "";
            for (auto [id, typeSize] : mCommandSpecifications[subCommandPath].requiredCommandFields)
            {
                auto [type, size] = typeSize;
                AddDefaultValueToPayload(payloadWithDefaults, std::to_string(id), type, size);
            }
            scPayload                          = Json::writeString(writer, payloadWithDefaults);
            std::string subcommandWithDefaults = scCommandSet + " " + scOperation + " " + scCluster + " " + scCommand + " " +
                scPayload + " " + scNode + " " + scEndpoint;
            mCommandHandler->ExecuteCommand(subcommandWithDefaults.c_str(), &subCommandErr);
            fuzz::Fuzzer::GetInstance()->GetStateMonitor()->TrackError(subCommandErr);
            if (subCommandErr == CHIP_ERROR_TIMEOUT)
            {
                consecutiveTimeouts++;
                if (consecutiveTimeouts > 1)
                {
                    return CHIP_ERROR_TIMEOUT;
                }
            }
            else
                consecutiveTimeouts = 0;
        }
        mCommandHandler->ExecuteCommand(subcommand.c_str(), &subCommandErr);
        fuzz::Fuzzer::GetInstance()->GetStateMonitor()->TrackError(subCommandErr);
        if (subCommandErr == CHIP_ERROR_TIMEOUT)
        {
            consecutiveTimeouts++;
            if (consecutiveTimeouts > 1)
                return CHIP_ERROR_TIMEOUT;
        }
        else
            consecutiveTimeouts = 0;
    }
    return CHIP_NO_ERROR;
}
