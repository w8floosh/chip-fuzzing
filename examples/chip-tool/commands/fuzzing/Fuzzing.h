#pragma once
#include "DeviceStateManager.h"
#include "Error.h"
#include "Oracle.h"
#include <app/tests/suites/commands/interaction_model/InteractionModel.h>
#include <filesystem>

namespace fs = std::filesystem;

class FuzzingStartCommand;
class FuzzingCommand;

namespace chip {
namespace fuzzing {

class Fuzzer
{
public:
    const char * GenerateCommand() { return mGenerationFunc(mSeedsDirectory); }
    static Fuzzer * GetInstance(std::function<Fuzzer()> * init = nullptr)
    {
        static Fuzzer f{ (*init)() };
        return &f;
    }

    // used in ClusterCommand::OnResponse callback
    void ProcessCommandOutput(chip::Protocols::InteractionModel::MsgType messageType, chip::TLV::TLVReader * data,
                              const chip::app::ConcreteCommandPath & path, const chip::app::StatusIB & status,
                              chip::app::StatusIB expectedStatus = chip::app::StatusIB());

    // used in ReportCommand::OnAttributeData and WriteAttributeCommand::OnResponse callbacks
    void ProcessCommandOutput(chip::Protocols::InteractionModel::MsgType messageType, chip::TLV::TLVReader * data,
                              const chip::app::ConcreteDataAttributePath & path, const chip::app::StatusIB & status,
                              chip::app::StatusIB expectedStatus = chip::app::StatusIB());

    // used in ReportCommand::OnEventData callback
    void ProcessCommandOutput(chip::Protocols::InteractionModel::MsgType messageType, const chip::app::EventHeader & eventHeader,
                              chip::TLV::TLVReader * data, const chip::app::StatusIB * status,
                              chip::app::StatusIB expectedStatus = chip::app::StatusIB());

    // used in OnError callbacks
    void ProcessCommandOutput(chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                              CHIP_ERROR expectedError = CHIP_NO_ERROR);
    DeviceStateManager * GetDeviceStateManager() { return &mDeviceStateManager; }

protected:
    friend class ::FuzzingStartCommand;

    static void Initialize(fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc)
    {
        std::function<Fuzzer()> init = [seedsDirectory, generationFunc]() { return Fuzzer(seedsDirectory, generationFunc); };
        GetInstance(&init);
    }
    static void Initialize(fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc, fs::path outputDirectory)
    {
        std::function<Fuzzer()> init = [seedsDirectory, generationFunc, outputDirectory]() {
            return Fuzzer(seedsDirectory, generationFunc, outputDirectory);
        };
        GetInstance(&init);
    }

    fs::path mSeedsDirectory;
    Optional<fs::path> mOutputDirectory = NullOptional;
    DeviceStateManager mDeviceStateManager;
    std::shared_ptr<Oracle> mOracle;

    // TODO: Should the fuzzer log oracle outputs too?
    CHIP_ERROR ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath);

private:
    Fuzzer(fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc) :
        mSeedsDirectory(seedsDirectory), mGenerationFunc(generationFunc) {};
    Fuzzer(fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc, fs::path outputDirectory) :
        mSeedsDirectory(seedsDirectory), mGenerationFunc(generationFunc)
    {
        mOutputDirectory.SetValue(outputDirectory);
    };
    Fuzzer(const Fuzzer &)                 = delete;
    Fuzzer(Fuzzer &&) noexcept             = delete;
    Fuzzer & operator=(const Fuzzer &)     = delete;
    Fuzzer & operator=(Fuzzer &&) noexcept = delete;

    std::function<const char *(fs::path)> mGenerationFunc;
};

std::function<const char *(fs::path)> ConvertStringToGenerationFunction(const char * key);
} // namespace fuzzing
} // namespace chip
