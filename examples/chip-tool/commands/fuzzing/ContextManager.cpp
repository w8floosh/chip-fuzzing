#include "ContextManager.h"
#include "Fuzzer.h"
#include "StateMonitor.h"
#include <app/InteractionModelEngine.h>
#include <thread>
bool fuzz::ContextManager::WaitForResponse(std::chrono::system_clock::time_point & waitingUntil)
{
    ChipLogDetail(chipFuzzer, "Waiting for response...");
    std::unique_lock<std::mutex> lk(*mContextMutex);
    return mCvContextMutex->wait_until(lk, waitingUntil, [this]() { return !(*mContext->waitingForResponse); });
}

// fuzz::ContextStatus & fuzz::ContextManager::CurrentStatus()
// {
//     std::unique_lock<std::mutex> lk(*mContextMutex);
//     VerifyOrDie(mContext != nullptr);
//     return mContext->status;
// }

void fuzz::ContextManager::Initialize(std::condition_variable * cv, std::mutex * mutex, bool * waitingForResponse)
{
    VerifyOrDie(cv != nullptr && mutex != nullptr && waitingForResponse != nullptr);
    std::unique_lock<std::mutex> lk(*mutex);

    std::unique_ptr<FuzzerContext> oldContext = nullptr;
    if (mContext)
        oldContext = std::make_unique<FuzzerContext>(*mContext);

    mContext                     = new FuzzerContext();
    mCvContextMutex              = cv;
    mContextMutex                = mutex;
    mContext->id                 = oldContext ? ++oldContext->id : 0;
    mContext->status             = ContextStatus::UNINITIALIZED;
    mContext->waitingForResponse = waitingForResponse;
    ChipLogProgress(chipFuzzer, "New fuzzer context initialized with id %d from thread %zu", mContext->id,
                    std::hash<std::thread::id>{}(std::this_thread::get_id()));
    auto ime = chip::app::InteractionModelEngine::GetInstance();
    ChipLogDetail(chipFuzzer, "Active read clients: %zu, dirty subscriptions: %zu", ime->GetNumActiveReadClients(),
                  ime->GetNumDirtySubscriptions());
}

CHIP_ERROR fuzz::ContextManager::RequireResponse()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    *mContext->waitingForResponse = true;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::RequireSubscriptionReport()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);

    auto fuzzer       = fuzz::Fuzzer::GetInstance();
    auto fuzzerPhase  = fuzzer->CurrentPhase();
    auto stateMonitor = fuzzer->GetStateMonitor();

    bool reportsEnabled  = fuzzerPhase == FuzzerPhase::TESTING || fuzzerPhase == FuzzerPhase::EXPLORATION;
    bool isInvokeCommand = mContext->commandPath.HasValue();
    if (isInvokeCommand && reportsEnabled && !stateMonitor->HasExceededSubscriptionTimeoutsLimit(mContext->commandPath.Value()))
        mContext->needsSubscriptionData = true;

    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::NotifyResponse()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    CHIP_ERROR err = CHIP_NO_ERROR;
    SuccessOrExit(err = (mContext ? CHIP_NO_ERROR : CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT));
    SuccessOrExit(err = (mContext->status != ContextStatus::TERMINATED ? CHIP_NO_ERROR : CHIP_FUZZER_ERROR_END_OF_CONTEXT));
    *mContext->waitingForResponse = false;
    ChipLogDetail(chipFuzzer, "Stopped waiting for response.");

exit:
    mCvContextMutex->notify_all();
    return err;
}

CHIP_ERROR fuzz::ContextManager::OnInvokeRequest(chip::NodeId dst, chip::app::ConcreteCommandPath commandPath)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    mContext->destination = dst;
    mContext->commandPath.SetValue(commandPath);
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to INVOKE_REQUEST.");
    mContext->status = ContextStatus::INVOKE_REQUEST;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::OnNonInvokeRequest(chip::NodeId dst)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);

    mContext->destination = dst;
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to NON_INVOKE_REQUEST.");
    mContext->status = ContextStatus::NON_INVOKE_REQUEST;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::OnNonInvokeResponse()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    VerifyOrReturnError(mContext->status == ContextStatus::NON_INVOKE_REQUEST, CHIP_FUZZER_ERROR_BAD_CONTEXT_STATE);

    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to NON_INVOKE_RESPONSE.");
    mContext->status = ContextStatus::NON_INVOKE_RESPONSE;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::OnInvokeResponse(CHIP_ERROR status)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status != ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);

    mContext->commandStatusResponse = status;
    auto fuzzer                     = fuzz::Fuzzer::GetInstance();
    auto commandPath                = mContext->commandPath.Value();

    if (fuzzer->CurrentPhase() == fuzz::FuzzerPhase::TESTING)
        fuzzer->GetOracle()->Consume(commandPath.mEndpointId, commandPath.mClusterId, commandPath.mCommandId, true, status);
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to INVOKE_RESPONSE.");
    mContext->status = ContextStatus::INVOKE_RESPONSE;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::ContextManager::OnSubscriptionReport(utils::DataAttributePathSet & attrs)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    CHIP_ERROR err = CHIP_NO_ERROR;
    SuccessOrExit(err = (mContext ? CHIP_NO_ERROR : CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT));
    SuccessOrExit(err = (mContext->status != ContextStatus::TERMINATED ? CHIP_NO_ERROR : CHIP_FUZZER_ERROR_END_OF_CONTEXT));
    SuccessOrExit(err = (mContext->status == ContextStatus::INVOKE_RESPONSE ? CHIP_NO_ERROR : CHIP_FUZZER_ERROR_BAD_CONTEXT_STATE));
    mContext->changedAttributes = attrs;
    ChipLogProgress(chipFuzzer, "Subscription data received");
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to SUBSCRIPTION_RESPONSE.");
    mContext->status = ContextStatus::SUBSCRIPTION_RESPONSE;

exit:
    // Notification required because sender is blocked on wait_until() inside WaitForSubscriptionReport() method
    mCvContextMutex->notify_all();
    return err;
}

CHIP_ERROR fuzz::ContextManager::WaitForSubscriptionReport()
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    CHIP_ERROR err    = CHIP_NO_ERROR;
    auto stateMonitor = fuzz::Fuzzer::GetInstance()->GetStateMonitor();
    SuccessOrExit(err = mContext ? CHIP_NO_ERROR : CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    if (mContext->needsSubscriptionData && mContext->status == ContextStatus::INVOKE_RESPONSE)
    {
        ChipLogDetail(chipFuzzer, "Waiting for subscription data...");
        bool subscriptionDataReceived =
            mCvContextMutex->wait_until(lk, std::chrono::system_clock::now() + std::chrono::seconds(3),
                                        [this] { return mContext->status == ContextStatus::SUBSCRIPTION_RESPONSE; });
        if (!subscriptionDataReceived)
        {
            ChipLogError(chipFuzzer, "Subscription data was not received in time.");
            err = CHIP_FUZZER_ERROR_SUBSCRIPTION_RESPONSE_TIMEOUT;
            stateMonitor->IncrementSubscriptionTimeouts(mContext->commandPath.Value());
        }
        else
        {
            ChipLogDetail(chipFuzzer, "Resetting subscription timeouts for command (%d, %d, %d)",
                          mContext->commandPath.Value().mEndpointId, mContext->commandPath.Value().mClusterId,
                          mContext->commandPath.Value().mCommandId);
            stateMonitor->ResetSubscriptionTimeouts(mContext->commandPath.Value());
        }
    }

exit:
    *mContext->waitingForResponse = false;
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to TERMINATED.");
    mContext->status = ContextStatus::TERMINATED;
    mCvContextMutex->notify_all();
    return err;
}

CHIP_ERROR fuzz::ContextManager::Close(bool log)
{
    std::unique_lock<std::mutex> lk(*mContextMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    VerifyOrReturnError(mContext->status == ContextStatus::TERMINATED, CHIP_FUZZER_ERROR_CONTEXT_LOCKED);

    auto stateMonitor = fuzz::Fuzzer::GetInstance()->GetStateMonitor();
    if (mContext->commandPath.HasValue() && log)
        stateMonitor->LogObservation(
            { mContext->commandPath.Value(), mContext->commandStatusResponse, mContext->changedAttributes });

    delete mContext;
    mContext = nullptr;
    return CHIP_NO_ERROR;
}
