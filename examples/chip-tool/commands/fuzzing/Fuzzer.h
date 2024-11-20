#pragma once
#include "CallbackInterceptor.h"
#include "ContextManager.h"
#include "DeviceStateTracker.h"
#include "ForwardDeclarations.h"
#include "Oracle.h"
#include "StateMonitor.h"
#include "specification/SpecificationEncoder.h"
class ClusterCommand;
class FuzzingCommand;
class FuzzingStartCommand;

namespace chip {

namespace fuzzing {

enum class FuzzerPhase : uint8_t
{
    INITIALIZATION,
    ACQUISITION,
    EXPLORATION,
    TESTING
};
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
    // const char * GenerateCommand() { return mGenerationFunc(mSeedsDirectory); }
    static Fuzzer * GetInstance(std::function<Fuzzer()> * init = nullptr)
    {
        static Fuzzer f{ (*init)() };
        return &f;
    }

    DeviceStateTracker * GetDeviceStateTracker() { return &mDeviceStateTracker; }
    ContextManager * GetContextManager() { return &mContextManager; }
    CallbackInterceptor * GetCallbackInterceptor() { return &mCallbackInterceptor; }
    StateMonitor * GetStateMonitor() { return &mStateMonitor; }
    Oracle * GetOracle() { return &mOracle; }
    spec::SpecificationEncoder * GetSpecificationEncoder() { return &mSpecificationEncoder; }
    FuzzerPhase CurrentPhase() { return mCurrentPhase; }
    std::string CurrentCommand() { return mCurrentCommand; }
    chip::app::ConcreteCommandPath CurrentAnalyzedPath() { return mCurrentAnalyzedPath; }
    NodeId CurrentDestination() { return mTarget; }

private:
    // FuzzingStartCommand must be a friend class as it is the only allowed to instantiate the Fuzzer class.
    friend class ::FuzzingCommand;
    friend class ::FuzzingStartCommand;

    // Fuzzer state data
    NodeId mTarget;
    size_t mTests;
    size_t mTestId = 0;
    std::string mCurrentCommand;
    FuzzerPhase mCurrentPhase = FuzzerPhase::INITIALIZATION;
    chip::app::ConcreteCommandPath mCurrentAnalyzedPath;
    Optional<fs::path> mOutputDirectory = NullOptional;
    fs::path mSeedsDirectory;
    std::vector<CommandHistoryEntry> mCommandHistory;
    const std::chrono::system_clock::time_point mStartTime;
    // Components
    specification::SpecificationEncoder mSpecificationEncoder;
    DeviceStateTracker mDeviceStateTracker;
    StateMonitor mStateMonitor;
    Oracle mOracle;
    CallbackInterceptor mCallbackInterceptor;
    ContextManager mContextManager;
    // TerminalUIManager mTerminalUIManager;

    Fuzzer(NodeId dst, fs::path outputDirectory, size_t tests, FuzzingCommand * executor);
    Fuzzer(const Fuzzer &)                 = delete;
    Fuzzer(Fuzzer &&) noexcept             = delete;
    Fuzzer & operator=(const Fuzzer &)     = delete;
    Fuzzer & operator=(Fuzzer &&) noexcept = delete;

    static void Initialize(NodeId dst, fs::path outputDirectory, size_t tests, FuzzingCommand * executor)
    {
        std::function<Fuzzer()> init = [dst, outputDirectory, tests, executor]() {
            return Fuzzer(dst, outputDirectory, tests, executor);
        };
        GetInstance(&init);
    }

    CHIP_ERROR ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath);
    CHIP_ERROR AppendToHistory(const char * command, CHIP_ERROR statusResponse)
    {
        mCommandHistory.push_back({ ++mTestId, std::string(command), statusResponse, mOracle.GetCurrentStatus() });
        return CHIP_NO_ERROR;
    }
    void GoToNextPhase()
    {
        VerifyOrReturn(mCurrentPhase != FuzzerPhase::TESTING);
        mCurrentPhase = static_cast<FuzzerPhase>((static_cast<uint8_t>(mCurrentPhase) + 1));
    }
    void Cleanup();
};

} // namespace fuzzing
} // namespace chip
