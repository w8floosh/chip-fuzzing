#pragma once
#include "DeviceStateManager.h"
#include "ForwardDeclarations.h"
#include "Oracle.h"
#include "tlv/DecodedTLVElement.h"
#include "tlv/TLVDataPayloadHelper.h"

class FuzzingCommand;
class FuzzingStartCommand;
namespace chip {
namespace fuzzing {
/**
 * @brief Generates mutated commands to test the CHIP device's behavior, as well as
 * saving the valid ones as future reference.
 *
 * This class is the starting point for response data analysis coming from the response
 * callbacks.
 *
 * There can be only one instance of the Fuzzer class, which is created by the FuzzingStartCommand class.
 */
class Fuzzer
{
public:
    const char * GenerateCommand() { return mGenerationFunc(mSeedsDirectory); }
    static Fuzzer * GetInstance(std::function<Fuzzer()> * init = nullptr)
    {
        static Fuzzer f{ (*init)() };
        return &f;
    }

    // Analyzes data coming from the ClusterCommand::OnResponse callback.
    void AnalyzeCommandResponse(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path,
                                const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus = chip::app::StatusIB());

    // Analyzes data coming from the ReportCommand::OnAttributeData and WriteAttributeCommand::OnResponse callbacks.
    void AnalyzeReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                           const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus = chip::app::StatusIB());

    // Analyzes data coming from the ReportCommand::OnEventData callback.
    void AnalyzeReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
                           const chip::app::StatusIB * status, chip::app::StatusIB expectedStatus = chip::app::StatusIB());

    // Analyzes data coming from the OnError callbacks.
    void AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                             CHIP_ERROR expectedError = CHIP_NO_ERROR);

    void ProcessDescriptorClusterResponse(std::shared_ptr<TLV::DecodedTLVElement> decoded,
                                          const chip::app::ConcreteDataAttributePath & path, NodeId node);

    DeviceStateManager * GetDeviceStateManager() { return &mDeviceStateManager; }

protected:
    // FuzzingStartCommand must be a friend class as it is the only allowed to instantiate the Fuzzer class.
    friend class ::FuzzingCommand;
    friend class ::FuzzingStartCommand;

    static void Initialize(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc)
    {
        std::function<Fuzzer()> init = [dst, seedsDirectory, generationFunc]() {
            return Fuzzer(dst, seedsDirectory, generationFunc);
        };
        GetInstance(&init);
    }
    static void Initialize(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc,
                           fs::path outputDirectory)
    {
        std::function<Fuzzer()> init = [dst, seedsDirectory, generationFunc, outputDirectory]() {
            return Fuzzer(dst, seedsDirectory, generationFunc, outputDirectory);
        };
        GetInstance(&init);
    }

    fs::path mSeedsDirectory;
    Optional<fs::path> mOutputDirectory = NullOptional;
    Optional<fs::path> mHistoryPath     = NullOptional;
    DeviceStateManager mDeviceStateManager;
    std::shared_ptr<Oracle> mOracle;

    // TODO: Should the fuzzer log oracle outputs too?
    CHIP_ERROR ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath);
    CHIP_ERROR AppendToHistory(const char * command)
    {
        mCommandHistory.push_back(std::string(command));
        return CHIP_NO_ERROR;
    }

private:
    Fuzzer(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc) :
        mSeedsDirectory(seedsDirectory), mOracle(new Oracle()), mGenerationFunc(generationFunc) {};
    Fuzzer(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc, fs::path outputDirectory) :
        mSeedsDirectory(seedsDirectory), mOracle(new Oracle()), mGenerationFunc(generationFunc)
    {
        mOutputDirectory.SetValue(outputDirectory);
    };
    Fuzzer(const Fuzzer &)                 = delete;
    Fuzzer(Fuzzer &&) noexcept             = delete;
    Fuzzer & operator=(const Fuzzer &)     = delete;
    Fuzzer & operator=(Fuzzer &&) noexcept = delete;

    // This callable object is the function responsible for generating the next command to be executed by the fuzzer.
    std::function<const char *(fs::path)> mGenerationFunc;
    NodeId mCurrentDestination;
    std::vector<std::string> mCommandHistory;
};

std::function<const char *(fs::path)> ConvertStringToGenerationFunction(const char * key);
} // namespace fuzzing
} // namespace chip
