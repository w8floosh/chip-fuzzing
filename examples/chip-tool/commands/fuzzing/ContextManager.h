#pragma once
#include "ForwardDeclarations.h"
#include "StateMonitor.h"
#include "Utils.h"
#include <condition_variable>
#include <mutex>
namespace chip {
namespace fuzzing {
/**
 * @brief The status of the current fuzzer context. It represents the last event occurred in the context.
 *
 */
class ContextStatus
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
    bool * waitingForResponse;
    bool needsSubscriptionData = false;
    ContextStatus status;

    uint32_t id;
    chip::NodeId destination;
    chip::Optional<chip::app::ConcreteCommandPath> commandPath = chip::NullOptional;
    char * commandString;
    CHIP_ERROR commandStatusResponse;
    utils::DataAttributePathSet changedAttributes;
};

class ContextManager
{
public:
    ContextManager() {}

    void Initialize(std::condition_variable * cv, std::mutex * mutex, bool * waitingForResponse);
    CHIP_ERROR RequireResponse();
    CHIP_ERROR RequireSubscriptionReport();
    CHIP_ERROR NotifyResponse();

    bool WaitForResponse(std::chrono::system_clock::time_point & waitingUntil);
    CHIP_ERROR WaitForSubscriptionReport();

    CHIP_ERROR OnInvokeRequest(chip::NodeId dst, chip::app::ConcreteCommandPath commandPath);
    CHIP_ERROR OnInvokeResponse(CHIP_ERROR status);
    CHIP_ERROR OnNonInvokeRequest(chip::NodeId dst);
    CHIP_ERROR OnNonInvokeResponse();
    CHIP_ERROR OnSubscriptionReport(utils::DataAttributePathSet & attrs);
    CHIP_ERROR OnResponseTimeout();

    CHIP_ERROR Close(bool log = false);

    bool IsInitialized() { return mContext != nullptr; }
    // ContextStatus & CurrentStatus();

private:
    FuzzerContext * mContext = nullptr;
    std::mutex * mContextMutex;
    std::condition_variable * mCvContextMutex;
};

} // namespace fuzzing
} // namespace chip
