#pragma once

#include "../clusters/DataModelLogger.h"
#include "../common/CHIPCommand.h"
#include "../common/Commands.h"
#include "Fuzzing.h"

namespace fuzz = chip::fuzzing;

class FuzzingCommand : public CHIPCommand
{
public:
    FuzzingCommand(const char * name, Commands * commandsHandler, const char * helpText,
                   CredentialIssuerCommands * credsIssuerConfig) :
        CHIPCommand(name, credsIssuerConfig, helpText), mHandler(commandsHandler)
    {}

    /////////// CHIPCommand Interface /////////
    chip::System::Clock::Timeout GetWaitDuration() const override { return chip::System::Clock::Seconds16(0); }
    void ExecuteCommand(const char * command, int * status);
    virtual CHIP_ERROR RunCommand() = 0;

private:
    Commands * mHandler = nullptr;
};

class FuzzingStartCommand : public FuzzingCommand
{
public:
    FuzzingStartCommand(Commands * commandsHandler, CredentialIssuerCommands * credsIssuerConfig) :
        FuzzingCommand("start", commandsHandler, "Start the fuzzing process that can then run other commands.", credsIssuerConfig)
    {

        // Initializing fuzzing options, taking the following arguments from command line
        AddArgument(
            "destination-id", 0, UINT64_MAX, &mDestinationId,
            "64-bit node or group identifier.\n  Group identifiers are detected by being in the 0xFFFF'FFFF'FFFF'xxxx range.");
        AddArgument("generation", &mGenerationFuncArgument, "Input generation function (seed-only, ...)");
        AddArgument("seed-path", &mSeedDirectoryArgument,
                    "Path where to read fuzzer seeds from and where to save correct commands");
        AddArgument("output-path", &mOutputDirectoryArgument,
                    "Path where to export stateful fuzzer logs. Enables stateful fuzzing");
        AddArgument("iterations", 0U, UINT32_MAX, &mIterations, "Number of iterations (commands) to run the fuzzer for");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    chip::NodeId mDestinationId;
    char * mGenerationFuncArgument;
    char * mSeedDirectoryArgument;
    chip::Optional<char *> mOutputDirectoryArgument = chip::NullOptional;
    chip::Optional<uint32_t> mIterations            = chip::Optional<uint32_t>::Value(1000);

    bool mStatefulFuzzingEnabled = false;
    fs::path mSeedDirectory;
    chip::Optional<fs::path> mOutputDirectory = chip::NullOptional;

    CHIP_ERROR InitializeFuzzer();

    CHIP_ERROR AcquireRemoteDataModel(chip::NodeId node);
    const char * GenerateCommand(chip::ClusterId cluster);
};
