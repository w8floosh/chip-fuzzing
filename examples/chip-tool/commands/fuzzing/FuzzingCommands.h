#pragma once

#include "../clusters/DataModelLogger.h"
#include "../common/CHIPCommand.h"
#include "../common/Commands.h"
#include "Fuzzers.h"

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
        AddArgument("fuzzer", &mFuzzerTypeArgument, "Fuzzer type (afl++, ...)");
        AddArgument("strategy", &mFuzzingStrategyArgument, "Fuzzing strategy");
        AddArgument("seed-path", &mSeedDirectoryArgument,
                    "Path where to read fuzzer seeds from and where to save correct commands");
        AddArgument("output-path", &mOutputDirectoryArgument,
                    "Path where to export stateful fuzzer logs. Enables stateful fuzzing");
        AddArgument("iterations", 0U, UINT32_MAX, &mIterations, "Number of iterations (commands) to run the fuzzer for");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    char * mFuzzerTypeArgument;
    char * mFuzzingStrategyArgument;
    char * mSeedDirectoryArgument;
    chip::Optional<char *> mOutputDirectoryArgument = chip::NullOptional;
    chip::Optional<uint32_t> mIterations            = chip::Optional<uint32_t>::Value(1000);

    fuzz::Fuzzer * mFuzzer;
    bool mStatefulFuzzingEnabled = false;
    fs::path mSeedDirectory;
    chip::Optional<fs::path> mOutputDirectory = chip::NullOptional;

    CHIP_ERROR InitializeFuzzer();
    CHIP_ERROR RetrieveNodeDescription(chip::NodeId node);
    const char * GenerateCommand(chip::ClusterId cluster);
};
