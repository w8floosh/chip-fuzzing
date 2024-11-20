#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"
#include <app/ConcreteCommandPath.h>
namespace chip {
namespace fuzzing {
class StateMonitor
{
public:
    StateMonitor(const std::chrono::system_clock::time_point & startTime,
                 fs::path dumpDir = "out/debug/standalone/chip-fuzzer/observations") :
        mDumpDirectory(dumpDir), mStartTime(startTime)
    {
        if (!fs::exists(mDumpDirectory))
        {
            fs::create_directories(mDumpDirectory);
        }
    }

    const std::chrono::system_clock::time_point & GetStartTime() { return mStartTime; }

    void DumpTelemetry();
    void LogObservation(const utils::FuzzerObservation & observation);

    /**
     * @brief Dumps the result of a command to a YAML file.
     */
    void IncrementSubscriptionTimeouts(const chip::app::ConcreteCommandPath & path) { mSubscriptionTimeouts[path]++; }
    void ResetSubscriptionTimeouts(const chip::app::ConcreteCommandPath & path) { mSubscriptionTimeouts[path] = 0U; }
    bool HasExceededSubscriptionTimeoutsLimit(const chip::app::ConcreteCommandPath & path)
    {
        return mSubscriptionTimeouts[path] >= 1U;
    }
    void TrackError(const CHIP_ERROR & err);
    void TrackError(const CHIP_ERROR & err, OracleResult & ores);
    // Used when a test case is skipped
    void TrackSkipped();

private:
    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mTestingErrorCounters;
    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mExplorationErrorCounters;

    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mExpectedErrorCounters;
    std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher> mUnexpectedErrorCounters;
    std::unordered_map<utils::FuzzerObservation, uint64_t, utils::MapKeyHasher, utils::MapKeyEqualizer> mObservationCounters;
    uint64_t mSkippedTests            = 0;
    uint64_t mSkippedExplorationTests = 0;
    /**
     * Tracks the number of times a command did not send any subscription report back, timing out.
     * After a command timed out three times IN A ROW, the fuzzer will not wait anymore for the subscription report to come.
     */
    std::unordered_map<chip::app::ConcreteCommandPath, uint16_t, utils::MapKeyHasher> mSubscriptionTimeouts;
    fs::path mDumpDirectory;
    const std::chrono::system_clock::time_point & mStartTime;

    void DumpObservation(const utils::FuzzerObservation & observation);
};
} // namespace fuzzing
} // namespace chip
