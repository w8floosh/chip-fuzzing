#pragma once
#include "DeviceStateManager.h"
#include "ForwardDeclarations.h"
#include "Oracle.h"
#include "tlv/DecodedTLVElement.h"
#include "tlv/TLVDataPayloadHelper.h"
#include <condition_variable>
#include <numeric>

class ClusterCommand;
class FuzzingCommand;
class FuzzingStartCommand;

namespace chip {

namespace fuzzing {
class StateMonitor
{
public:
    StateMonitor(fs::path dumpDir = "out/debug/standalone/chip-fuzzer/observations") : mDumpDirectory(dumpDir)
    {
        if (!fs::exists(mDumpDirectory))
        {
            fs::create_directories(mDumpDirectory);
        }
    }

    std::tuple<size_t, size_t, size_t> GetErrorCounters()
    {
        return { mErrorCounters.size(), mExpectedErrorCounters.size(), mUnexpectedErrorCounters.size() };
    }
    void DumpTelemetry() {}
    void LogObservation(const utils::FuzzerObservation & observation);

    /**
     * @brief Dumps the result of a command to a YAML file.
     */
    void IncrementSubscriptionTimeouts(const chip::app::ConcreteCommandPath & path) { mSubscriptionTimeouts[path]++; }
    void ResetSubscriptionTimeouts(const chip::app::ConcreteCommandPath & path) { mSubscriptionTimeouts[path] = 0U; }
    bool HasExceededSubscriptionTimeoutsLimit(const chip::app::ConcreteCommandPath & path)
    {
        return mSubscriptionTimeouts[path] >= 3U;
    }
    void TrackError(const CHIP_ERROR & err) { mErrorCounters[err]++; }
    void TrackError(const CHIP_ERROR & err, OracleResult & ores)
    {
        mErrorCounters[err]++;
        ores.queryResult ? mExpectedErrorCounters[err]++ : mUnexpectedErrorCounters[err]++;
    }

private:
    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mErrorCounters;
    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mExpectedErrorCounters;
    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mUnexpectedErrorCounters;
    std::unordered_map<utils::FuzzerObservation, uint64_t, utils::MapKeyHasher, utils::MapKeyEqualizer> mObservationCounters;
    /**
     * Tracks the number of times a command did not send any subscription report back, timing out.
     * After a command timed out three times IN A ROW, the fuzzer will not wait anymore for the subscription report to come.
     */
    std::unordered_map<chip::app::ConcreteCommandPath, uint16_t, utils::MapKeyHasher> mSubscriptionTimeouts;
    fs::path mDumpDirectory;

    void DumpObservation(const utils::FuzzerObservation & observation);
    bool IsObservationUnseen(const utils::FuzzerObservation & observation)
    {
        return mObservationCounters.find(observation) == mObservationCounters.end();
    }
};

/**
 * @brief The status of the current fuzzer context. It represents the last event occurred in the context.
 *
 */
class FuzzerContextStatus
{
public:
    enum Status : uint8_t
    {
        UNINITIALIZED,
        NON_INVOKE_REQUEST,
        INVOKE_REQUEST,
        NON_INVOKE_RESPONSE,
        INVOKE_RESPONSE,
        SUBSCRIPTION_RESPONSE,
        TERMINATED
    };
    bool operator>=(Status rhs) { return static_cast<uint8_t>(mStatus) >= static_cast<uint8_t>(rhs); }
    bool operator<(Status rhs) { return static_cast<uint8_t>(mStatus) < static_cast<uint8_t>(rhs); }
    void operator=(Status rhs) { mStatus = rhs; }
    bool operator==(Status rhs) { return mStatus == rhs; }
    bool operator!=(Status rhs) { return mStatus != rhs; }
    uint8_t AsInteger() { return static_cast<uint8_t>(mStatus); }

private:
    Status mStatus = UNINITIALIZED;
};

struct FuzzerContext
{
    std::condition_variable * cv;
    std::mutex * mutex;
    bool * waitingForResponse;
    bool waitingForSubscriptionData = false;
    bool needsSubscriptionData      = false;
    uint32_t id;
    chip::NodeId destination;
    FuzzerContextStatus status;
    chip::Optional<chip::app::ConcreteCommandPath> commandPath = chip::NullOptional;
    CHIP_ERROR * commandStatusResponse;
    utils::DataAttributePathSet changedAttributes;
};
class FuzzerContextManager
{
public:
    FuzzerContextManager() = delete;
    FuzzerContextManager(StateMonitor & pm) : mStateMonitor(pm) {}

    void Initialize(std::condition_variable * cv, std::mutex * mutex, bool * waitingForResponse);
    CHIP_ERROR Update(CHIP_ERROR * err);
    CHIP_ERROR Update(chip::NodeId dst, CHIP_ERROR * err);
    CHIP_ERROR Update(chip::NodeId dst, chip::app::ConcreteCommandPath commandPath, CHIP_ERROR * err);
    CHIP_ERROR Update(utils::DataAttributePathSet attrs);
    CHIP_ERROR Update(chip::Optional<bool> waitingForResponse, chip::Optional<bool> waitingForSubscriptionData);
    CHIP_ERROR Finalize();
    CHIP_ERROR MoveToState(FuzzerContextStatus::Status newState)
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
        std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
        VerifyOrReturnError(mContext->status < newState, CHIP_FUZZER_ERROR_CONTEXT_LOCKED);
        mContext->status = newState;
        return CHIP_NO_ERROR;
    }

    CHIP_ERROR Close(bool skipErrors = false)
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        VerifyOrReturnError(mContext || skipErrors, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
        {
            std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
            VerifyOrReturnError(mContext->status == FuzzerContextStatus::TERMINATED || skipErrors,
                                CHIP_FUZZER_ERROR_CONTEXT_LOCKED);
            delete mContext;
        }
        mContext = nullptr;
        return CHIP_NO_ERROR;
    }

    bool IsInitialized()
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        return mContext != nullptr;
    }
    FuzzerContextStatus & CurrentStatus()
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        VerifyOrDie(mContext != nullptr);
        std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
        return mContext->status;
    }

    bool WaitForContextUpdate(std::chrono::system_clock::time_point & waitingUntil)
    {
        std::unique_lock<std::mutex> lk(*mContext->mutex);
        return mContext->cv->wait_until(lk, waitingUntil, [this]() { return !(*mContext->waitingForResponse); });
    }

private:
    FuzzerContext * mContext = nullptr;
    std::mutex mContextManagerMutex;
    StateMonitor & mStateMonitor;
};

class CallbackInterceptor
{
public:
    CallbackInterceptor() = delete;
    CallbackInterceptor(DeviceStateManager & deviceStateManager, Oracle & oracle, NodeId & dst) :
        mDeviceStateManager(deviceStateManager), mOracle(oracle), mCurrentDestination(dst)
    {}
    // Analyzes data coming from the ClusterCommand::OnResponse callback.
    void AnalyzeCommandResponse(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path,
                                const chip::app::StatusIB & status);

    // Analyzes data coming from the ReportCommand::OnAttributeData and WriteAttributeCommand::OnResponse callbacks.
    void ProcessReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                           const chip::app::StatusIB & status);

    // Analyzes data coming from the ReportCommand::OnEventData callback.
    void ProcessReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
                           const chip::app::StatusIB * status);

    /**
     * Analyzes a recoverable error occurred while reporting, i.e. errors on single attributes in a transaction that involves
     * multiple ones. Currently it is only used when a read operation on an attribute with manufacturer-specific default value
     * conformance is done. In such case, the attribute value is uninitialized and it needs to be written at least once before
     * attempting a successful read.
     */
    void AnalyzeReportError(const chip::app::ConcreteDataAttributePath & path, const chip::app::StatusIB & status);

    // Analyzes data coming from the OnError callbacks.
    void AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                             CHIP_ERROR expectedError = CHIP_NO_ERROR);

private:
    DeviceStateManager & mDeviceStateManager;
    Oracle & mOracle;
    NodeId & mCurrentDestination;
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
    const char * GenerateCommand() { return mGenerationFunc(mSeedsDirectory); }
    static Fuzzer * GetInstance(std::function<Fuzzer()> * init = nullptr)
    {
        static Fuzzer f{ (*init)() };
        return &f;
    }

    DeviceStateManager * GetDeviceStateManager() { return &mDeviceStateManager; }
    FuzzerContextManager * GetContextManager() { return &mContextManager; };
    CallbackInterceptor * GetCallbackInterceptor() { return &mCallbackInterceptor; }
    StateMonitor * GetStateMonitor() { return &mStateMonitor; }
    Oracle * GetOracle() { return &mOracle; }

protected:
    // FuzzingStartCommand must be a friend class as it is the only allowed to instantiate the Fuzzer class.
    friend class ::FuzzingCommand;
    friend class ::FuzzingStartCommand;

    DeviceStateManager mDeviceStateManager;
    StateMonitor mStateMonitor;
    Oracle mOracle;
    CallbackInterceptor mCallbackInterceptor;
    FuzzerContextManager mContextManager;

    fs::path mSeedsDirectory;
    Optional<fs::path> mOutputDirectory = NullOptional;
    Optional<fs::path> mHistoryPath     = NullOptional;

    static void Initialize(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc,
                           fs::path dumpDirectory)
    {
        std::function<Fuzzer()> init = [dst, seedsDirectory, generationFunc, dumpDirectory]() {
            return Fuzzer(dst, seedsDirectory, generationFunc, dumpDirectory);
        };
        GetInstance(&init);
    }
    static void Initialize(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc,
                           fs::path dumpDirectory, fs::path outputDirectory)
    {
        std::function<Fuzzer()> init = [dst, seedsDirectory, generationFunc, dumpDirectory, outputDirectory]() {
            return Fuzzer(dst, seedsDirectory, generationFunc, dumpDirectory, outputDirectory);
        };
        GetInstance(&init);
    }

    CHIP_ERROR ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath);
    CHIP_ERROR AppendToHistory(const char * command, CHIP_ERROR statusResponse)
    {
        mCommandHistory.push_back(CommandHistoryEntry{ std::string(command), statusResponse, mOracle.GetCurrentStatus() });
        return CHIP_NO_ERROR;
    }

private:
    Fuzzer(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc, fs::path dumpDirectory) :
        mDeviceStateManager(dumpDirectory), mOracle(mStateMonitor),
        mCallbackInterceptor(mDeviceStateManager, mOracle, mCurrentDestination), mContextManager(mStateMonitor),
        mSeedsDirectory(seedsDirectory), mGenerationFunc(generationFunc), mCurrentDestination(dst) {};
    Fuzzer(NodeId dst, fs::path seedsDirectory, std::function<const char *(fs::path)> generationFunc, fs::path dumpDirectory,
           fs::path outputDirectory) :
        mDeviceStateManager(dumpDirectory), mOracle(mStateMonitor),
        mCallbackInterceptor(mDeviceStateManager, mOracle, mCurrentDestination), mContextManager(mStateMonitor),
        mSeedsDirectory(seedsDirectory), mGenerationFunc(generationFunc), mCurrentDestination(dst)
    {
        mOutputDirectory.SetValue(outputDirectory);
    };
    Fuzzer(const Fuzzer &)                 = delete;
    Fuzzer(Fuzzer &&) noexcept             = delete;
    Fuzzer & operator=(const Fuzzer &)     = delete;
    Fuzzer & operator=(Fuzzer &&) noexcept = delete;

    // This callable object is the function responsible for generating the next command to be executed by the fuzzer.
    // May be used to extend the fuzzer to use diverse generation methods aside the default one (Grammarinator).
    std::function<const char *(fs::path)> mGenerationFunc;
    NodeId mCurrentDestination;
    std::vector<CommandHistoryEntry> mCommandHistory;
};

std::function<const char *(fs::path)> ConvertStringToGenerationFunction(const char * key);
} // namespace fuzzing
} // namespace chip
