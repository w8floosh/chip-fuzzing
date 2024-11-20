#pragma once
#include "../common/CHIPCommand.h"
#include "../common/Commands.h"
#include "ForwardDeclarations.h"
#include "Fuzzer.h"

namespace fuzz = chip::fuzzing;
namespace fs   = std::filesystem;
using IMStatus = fuzz::IMStatus;
class FuzzingCommand : public CHIPCommand
{
public:
    FuzzingCommand(const char * name, Commands * commandsHandler, const char * helpText,
                   CredentialIssuerCommands * credsIssuerConfig) :
        CHIPCommand(name, credsIssuerConfig, helpText), mHandler(commandsHandler)
    {}

    /////////// CHIPCommand Interface /////////
    chip::System::Clock::Timeout GetWaitDuration() const override { return chip::System::Clock::Seconds16(0); }
    void ExecuteCommand(const char * command, CHIP_ERROR * status);
    virtual CHIP_ERROR RunCommand() override = 0;

private:
    Commands * mHandler = nullptr;
};

/**
 * @brief Starts the fuzzing process that can then run other commands.
 */
class FuzzingStartCommand : public FuzzingCommand
{
public:
    FuzzingStartCommand(Commands * commandsHandler, CredentialIssuerCommands * credsIssuerConfig) :
        FuzzingCommand("start", commandsHandler, "Start the fuzzing process that can then run other commands.", credsIssuerConfig)
    {

        // Initializing fuzzing options, taking the following arguments from command line
        AddArgument("destination-id", 0, UINT64_MAX, &mDestinationId,
                    "64-bit node or group identifier.\n  Group identifiers are detected by being in the 0xFFFF'FFFF'FFFF'xxxx "
                    "range. Group fuzzing is not yet supported.");
        AddArgument("tests", 0U, UINT64_MAX, &mTests, "Number of test cases to run the fuzzer for");
        AddArgument("output-path", &mOutputDirectoryArgument,
                    "Output path for saving fuzzer data, including device grammar files, test cases and temporary files.");
        // AddArgument("generation", &mGenerationFuncArgument, "Input generation function (seed-only, ...)");
        // AddArgument("seed-path", &mSeedDirectoryArgument,
        //             "Path where to read fuzzer seeds from and where to save correct commands");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    chip::NodeId mDestinationId;
    size_t mTests                      = 1000U;
    bool mDestinationSupportsTCPServer = false;

    char * mOutputDirectoryArgument;
    chip::Optional<fs::path> mOutputDirectory = chip::NullOptional;

    CHIP_ERROR InitializeFuzzer();
    CHIP_ERROR AcquireRemoteDataModel();
    CHIP_ERROR AcquireBasicInformation();
    bool TestTCPServerSupport();
    CHIP_ERROR SubscribeAttributes();
    CHIP_ERROR AddOracleRules(chip::Optional<fs::path> dependencyTestFile);
};
