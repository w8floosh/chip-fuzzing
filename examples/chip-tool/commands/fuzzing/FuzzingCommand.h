#include "../clusters/DataModelLogger.h"
#include "../common/CHIPCommand.h"
#include "../common/Commands.h"
#include "Fuzzing.h"
#include "StatefulFuzzing.h"

namespace fuzz = chip::fuzzing;

class FuzzingCommand : public CHIPCommand
{
public:
    FuzzingCommand(const char * name, Commands * commandsHandler, const char * helpText,
                   CredentialIssuerCommands * credsIssuerConfig) :
        CHIPCommand(name, credsIssuerConfig, helpText), mHandler(commandsHandler)
    {

        char * aFuzzerType      = nullptr;
        char * aFuzzingStrategy = nullptr;
        char * aSeedDirectory   = nullptr;
        char * aOutputDirectory = nullptr;

        AddArgument("fuzzer", &aFuzzerType, "Fuzzer type (afl++, ...)");
        AddArgument("fuzzing-strategy", &aFuzzingStrategy, "Fuzzing strategy");
        AddArgument("seed-path", &aSeedDirectory,
                    "Path where to read fuzzer seeds from. Also specifies where to save correct commands.");
        AddArgument("log-path", &aSeedDirectory, "Path where to export stateful fuzzer logs. Enables stateful fuzzing");

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
        VerifyOrDieWithMsg(fs::exists(mSeedDirectory), chipFuzzer, "Seed path does not exist");

        if (aOutputDirectory != nullptr)
        {
            mStatefulFuzzingEnabled = true;
            mOutputDirectory.SetValue(fs::path(aOutputDirectory));
            free(aOutputDirectory);
            aOutputDirectory = nullptr;
        }

        CHIP_ERROR err;
        if (mStatefulFuzzingEnabled)
        {
            err = fuzz::stateful::Init(*kFuzzerType, *kFuzzingStrategy, mSeedDirectory, mOutputDirectory, &mFuzzer);
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
        free(aOutputDirectory);
        VerifyOrDieWithMsg(err == CHIP_NO_ERROR, chipFuzzer, "Failed to initialize fuzzer");
    }

    /////////// CHIPCommand Interface /////////
    CHIP_ERROR RunCommand() override;
    char * GenerateCommand(chip::ClusterId cluster);
    chip::System::Clock::Timeout GetWaitDuration() const override { return chip::System::Clock::Seconds16(0); }

private:
    Commands * mHandler = nullptr;
    fuzz::Fuzzer * mFuzzer;
    chip::Optional<bool> mAdvertiseOperational;
    bool mStatefulFuzzingEnabled = false;
    fs::path mSeedDirectory;
    chip::Optional<fs::path> mOutputDirectory = chip::NullOptional;
};
