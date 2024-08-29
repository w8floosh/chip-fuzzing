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

private:
    Commands * mHandler = nullptr;
    chip::Optional<bool> mAdvertiseOperational;
};

class FuzzingStartCommand : public FuzzingCommand
{
public:
    FuzzingStartCommand(Commands * commandsHandler, CredentialIssuerCommands * credsIssuerConfig) :
        FuzzingCommand("start", commandsHandler, "Start the fuzzing process that can then run other commands.", credsIssuerConfig)
    {

        // Initializing fuzzing options, taking the following arguments from command line
        char * aFuzzerType      = nullptr;
        char * aFuzzingStrategy = nullptr;
        char * aSeedDirectory   = nullptr;
        char * aOutputDirectory = nullptr;
        char * aIterations      = nullptr;

        AddArgument("fuzzer", &aFuzzerType, "Fuzzer type (afl++, ...)");
        AddArgument("fuzzing-strategy", &aFuzzingStrategy, "Fuzzing strategy");
        AddArgument("seed-path", &aSeedDirectory, "Path where to read fuzzer seeds from and where to save correct commands");
        AddArgument("log-path", &aOutputDirectory, "Path where to export stateful fuzzer logs. Enables stateful fuzzing");
        AddArgument("iterations", &aIterations, "Number of iterations (commands) to run the fuzzer for");

        VerifyOrDieWithMsg((aFuzzerType == nullptr) == (aFuzzingStrategy == nullptr), chipFuzzer,
                           "Both fuzzer type and strategy must be specified to enable fuzzing");

        fuzz::FuzzerType * kFuzzerType = fuzz::ConvertStringToFuzzerType(aFuzzerType);
        VerifyOrDieWithMsg((aFuzzerType != nullptr) != (kFuzzerType == nullptr), chipFuzzer,
                           "Specified fuzzer type is not implemented");

        fuzz::FuzzingStrategy * kFuzzingStrategy = fuzz::ConvertStringToFuzzingStrategy(aFuzzingStrategy);
        VerifyOrDieWithMsg((aFuzzingStrategy != nullptr) != (kFuzzingStrategy == nullptr), chipFuzzer,
                           "Specified fuzzer type is not implemented");

        VerifyOrDieWithMsg(aSeedDirectory != nullptr, chipFuzzer, "Seed path must be specified");

        mSeedDirectory = fs::path(aSeedDirectory);
        free(aSeedDirectory);
        aSeedDirectory = nullptr;
        VerifyOrDieWithMsg(fs::exists(mSeedDirectory), chipFuzzer, "Seed path does not exist");

        if (aIterations != nullptr)
        {
            mIterations = atoi(aIterations);
            free(aIterations);
            aIterations = nullptr;
        }

        if (aOutputDirectory != nullptr)
        {
            mStatefulFuzzingEnabled = true;
            mOutputDirectory.SetValue(fs::path(aOutputDirectory));
            free(aOutputDirectory);
            aOutputDirectory = nullptr;
            VerifyOrDieWithMsg(fs::exists(mOutputDirectory.Value()), chipFuzzer, "Output path does not exist");
        }

        // Fuzzer instance initialization
        CHIP_ERROR err;

        if (mStatefulFuzzingEnabled)
        {
            err = fuzz::Init(*kFuzzerType, *kFuzzingStrategy, mSeedDirectory, mOutputDirectory.Value(), &mFuzzer);
        }
        else
        {
            err = fuzz::Init(*kFuzzerType, *kFuzzingStrategy, mSeedDirectory, &mFuzzer);
        }

        if (kFuzzerType != nullptr)
        {
            free(kFuzzerType);
            kFuzzerType = nullptr;
        }

        if (kFuzzingStrategy != nullptr)
        {
            free(kFuzzingStrategy);
            kFuzzingStrategy = nullptr;
        }

        VerifyOrDieWithMsg(err == CHIP_NO_ERROR, chipFuzzer, "Failed to initialize fuzzer");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;

private:
    fuzz::Fuzzer * mFuzzer;
    int mIterations              = 1000;
    bool mStatefulFuzzingEnabled = false;
    fs::path mSeedDirectory;
    chip::Optional<fs::path> mOutputDirectory = chip::NullOptional;

    CHIP_ERROR RetrieveNodeDescription(chip::NodeId node);
    char * GenerateCommand(chip::ClusterId cluster);
};
