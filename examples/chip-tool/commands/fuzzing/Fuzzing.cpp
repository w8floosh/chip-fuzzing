#include "Fuzzing.h"
#include "Utils.h"
#include "Visitors.h"
#include "generation/Wrappers.cpp"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <map>
#include <thread>

namespace fuzz = chip::fuzzing;
void fuzz::CallbackInterceptor::AnalyzeCommandResponse(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path,
                                                       const chip::app::StatusIB & status)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(path.mEndpointId, path.mClusterId, path.mCommandId);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLV::TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        TLV::DecodedTLVElementPrettyPrinter(output).Print();
        // // TODO: To modify the local device state, we process the subscription response
        // // TODO: [DISCLAIMER] We assume the request-response-subscription_response flow is synchronous (in this order)
    }

    mOracle.Consume(path.mEndpointId, path.mClusterId, path.mCommandId, true, status);
}

void fuzz::CallbackInterceptor::ProcessReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                                                  const chip::app::StatusIB & status)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(path);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLV::TLVType::kTLVType_Structure);

        VerifyOrDie(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        TLV::DecodedTLVElementPrettyPrinter(output).Print();

        if (path.mClusterId == chip::app::Clusters::Descriptor::Id)
        {
            switch (path.mAttributeId)
            {
            case chip::app::Clusters::Descriptor::Attributes::PartsList::Id: {
                Visitors::TLV::ProcessDescriptorClusterResponse<EndpointId>(output, path, mCurrentDestination);
                break;
            }
            case chip::app::Clusters::Descriptor::Attributes::DeviceTypeList::Id:
            case chip::app::Clusters::Descriptor::Attributes::ServerList::Id: {
                // This case also applies to the DeviceTypeId: both types are uint32_t
                Visitors::TLV::ProcessDescriptorClusterResponse<ClusterId>(output, path, mCurrentDestination);
                break;
            }
            }
        }
        else if (path.mClusterId == chip::app::Clusters::BasicInformation::Id)
        {
            Visitors::TLV::ProcessBasicInformationClusterResponse(output, path, mCurrentDestination);
        }
        else
        {
            auto & attributeState =
                mDeviceStateManager.GetAttributeState(mCurrentDestination, path.mEndpointId, path.mClusterId, path.mAttributeId);
            helper.WriteToDeviceState(std::move(output), attributeState);
        }
    }

    mOracle.Consume(path.mEndpointId, path.mClusterId, path.mAttributeId, false, status);
}

void fuzz::CallbackInterceptor::ProcessReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
                                                  const chip::app::StatusIB * status)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(eventHeader);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLV::TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        TLV::DecodedTLVElementPrettyPrinter(output).Print();
    }

    mOracle.Consume(eventHeader.mPath.mEndpointId, eventHeader.mPath.mClusterId, eventHeader.mPath.mEventId, false, *status);
}

void fuzz::CallbackInterceptor::AnalyzeReportError(const chip::app::ConcreteDataAttributePath & path,
                                                   const chip::app::StatusIB & status)
{
    auto & attributeState =
        mDeviceStateManager.GetAttributeState(mCurrentDestination, path.mEndpointId, path.mClusterId, path.mAttributeId);
    if (attributeState.IsReadable())
        attributeState.ToggleBlockReads();
    mOracle.Consume(path.mEndpointId, path.mClusterId, path.mAttributeId, false, status);
}

void fuzz::CallbackInterceptor::AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                                                    CHIP_ERROR expectedError)
{}

void fuzz::FuzzerContextManager::Initialize(std::condition_variable * cv, std::mutex * mutex, bool * waitingForResponse)
{
    VerifyOrDie(cv != nullptr && mutex != nullptr && waitingForResponse != nullptr);
    std::unique_lock<std::mutex> lk(mContextManagerMutex);
    std::unique_lock<std::mutex> ctxlk(*mutex);

    std::unique_ptr<FuzzerContext> oldContext = nullptr;
    if (mContext)
        oldContext = std::make_unique<FuzzerContext>(*mContext);

    mContext                             = new FuzzerContext();
    mContext->cv                         = cv;
    mContext->mutex                      = mutex;
    mContext->id                         = oldContext ? ++oldContext->id : 0;
    mContext->status                     = FuzzerContextStatus::UNINITIALIZED;
    mContext->waitingForResponse         = waitingForResponse;
    mContext->waitingForSubscriptionData = false;
    ChipLogProgress(chipFuzzer, "New fuzzer context initialized with id %d from thread %zu", mContext->id,
                    std::hash<std::thread::id>{}(std::this_thread::get_id()));
}

CHIP_ERROR fuzz::FuzzerContextManager::Update(chip::NodeId dst, chip::app::ConcreteCommandPath commandPath, CHIP_ERROR * err)
{
    std::unique_lock<std::mutex> lk(mContextManagerMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
    VerifyOrReturnError(mContext->status != FuzzerContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    mContext->destination = dst;
    mContext->commandPath.SetValue(commandPath);
    mContext->commandStatusResponse = err;
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to INVOKE_REQUEST.");
    mContext->status = FuzzerContextStatus::INVOKE_REQUEST;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::FuzzerContextManager::Update(chip::Optional<bool> waitingForResponse,
                                              chip::Optional<bool> waitingForSubscriptionData)
{
    std::unique_lock<std::mutex> lk(mContextManagerMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
    if (waitingForResponse.HasValue())
        *mContext->waitingForResponse = waitingForResponse.Value();
    if (waitingForSubscriptionData.HasValue())
    {
        mContext->waitingForSubscriptionData = waitingForSubscriptionData.Value();
        if (mContext->waitingForSubscriptionData && mContext->commandPath.HasValue() &&
            !mStateMonitor.HasExceededSubscriptionTimeoutsLimit(mContext->commandPath.Value()))
            mContext->needsSubscriptionData = true;
    }
    ChipLogProgress(chipFuzzer, "New context flags state: [res: %d, sub: %d]", *mContext->waitingForResponse,
                    mContext->waitingForSubscriptionData);

    if (!waitingForResponse.ValueOr(true))
        mContext->cv->notify_all();

    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::FuzzerContextManager::Update(chip::NodeId dst, CHIP_ERROR * err)
{
    std::unique_lock<std::mutex> lk(mContextManagerMutex);
    VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
    VerifyOrReturnError(mContext->status != FuzzerContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    mContext->destination           = dst;
    mContext->commandStatusResponse = err;
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to NON_INVOKE_REQUEST.");
    mContext->status = FuzzerContextStatus::NON_INVOKE_REQUEST;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::FuzzerContextManager::Update(CHIP_ERROR * err)
{
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    }
    std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
    VerifyOrReturnError(mContext->status != FuzzerContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    mContext->commandStatusResponse = err;
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to NON_INVOKE_RESPONSE.");
    mContext->status = FuzzerContextStatus::NON_INVOKE_RESPONSE;
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::FuzzerContextManager::Update(utils::DataAttributePathSet attrs)
{
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    }
    std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
    VerifyOrReturnError(mContext->status != FuzzerContextStatus::TERMINATED, CHIP_FUZZER_ERROR_END_OF_CONTEXT);
    mContext->changedAttributes = attrs;
    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to SUBSCRIPTION_RESPONSE.");
    mContext->status = FuzzerContextStatus::SUBSCRIPTION_RESPONSE;

    // Notification required because sender is blocked on wait_until() inside Finalize() method
    mContext->cv->notify_all();

    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::FuzzerContextManager::Finalize()
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    {
        std::unique_lock<std::mutex> lk(mContextManagerMutex);
        VerifyOrReturnError(mContext, CHIP_FUZZER_ERROR_UNINITIALIZED_CONTEXT);
    }
    std::unique_lock<std::mutex> ctxlk(*mContext->mutex);
    if (mContext->needsSubscriptionData && mContext->status == FuzzerContextStatus::INVOKE_RESPONSE)
    {
        ChipLogProgress(chipFuzzer, "Waiting for subscription data...");
        bool subscriptionDataReceived =
            (*mContext->cv).wait_until(ctxlk, std::chrono::system_clock::now() + std::chrono::seconds(3), [this] {
                return mContext->status == FuzzerContextStatus::SUBSCRIPTION_RESPONSE;
            });
        if (!subscriptionDataReceived)
        {
            ChipLogError(chipFuzzer, "Subscription data was not received in time.");
            err = CHIP_FUZZER_ERROR_SUBSCRIPTION_RESPONSE_TIMEOUT;
            mStateMonitor.IncrementSubscriptionTimeouts(mContext->commandPath.Value());
        }
        else
        {
            ChipLogDetail(chipFuzzer, "Resetting subscription timeouts for command (%d, %d, %d)",
                          mContext->commandPath.Value().mEndpointId, mContext->commandPath.Value().mClusterId,
                          mContext->commandPath.Value().mCommandId);
            mStateMonitor.ResetSubscriptionTimeouts(mContext->commandPath.Value());
        }
    }

    *mContext->waitingForResponse = false;
    ChipLogProgress(chipFuzzer, "New context flags state: [res: %d, sub: %d]", *mContext->waitingForResponse,
                    mContext->waitingForSubscriptionData);

    ChipLogProgress(chipFuzzer, "Moving fuzzer context state to TERMINATED.");
    mContext->status = FuzzerContextStatus::TERMINATED;
    if (mContext->commandPath.HasValue())
        mStateMonitor.LogObservation(
            { mContext->commandPath.Value(), *mContext->commandStatusResponse, mContext->changedAttributes });

    mContext->cv->notify_all();

    return err;
}

void fuzz::StateMonitor::LogObservation(const utils::FuzzerObservation & observation)
{
    if (IsObservationUnseen(observation))
    {
        DumpObservation(observation);
    }
    mObservationCounters[observation]++;
}

void fuzz::StateMonitor::DumpObservation(const utils::FuzzerObservation & observation)
{
    YAML::Emitter os;

    os << YAML::BeginMap;
    os << YAML::Key << "endpoint" << YAML::Value << observation.mCommandPath.mEndpointId;
    os << YAML::Key << "cluster" << YAML::Value << observation.mCommandPath.mClusterId;
    os << YAML::Key << "command" << YAML::Value << observation.mCommandPath.mCommandId;
    os << YAML::Key << "statusResponse" << YAML::Value << YAML::Hex << observation.mStatusResponse.AsInteger() << YAML::Dec;
    os << YAML::Key << "changedAttributes" << YAML::Value << YAML::BeginSeq;
    for (auto & path : observation.mChangedAttributes)
    {
        os << YAML::BeginMap;
        os << YAML::Key << "endpoint" << YAML::Value << path.mEndpointId;
        os << YAML::Key << "cluster" << YAML::Value << path.mClusterId;
        os << YAML::Key << "attribute" << YAML::Value << path.mAttributeId;
        // TODO: maybe also log the new value?
        // os << YAML::Key << "newValue" << YAML::Value << path.mData;
        os << YAML::EndMap;
    }
    os << YAML::EndSeq << YAML::EndMap;
    auto now    = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::string fileName(std::to_string(now_ms));
    std::ofstream file(mDumpDirectory / fileName);
    file << os.c_str();
    file.close();
}

CHIP_ERROR fuzz::Fuzzer::ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath)
{
    namespace fs = std::filesystem;
    auto now     = std::chrono::system_clock::now();
    auto now_ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // Create seed hash from current timestamp
    std::hash<std::string> hasher;
    size_t hashedValue = hasher(std::to_string(now_ms));

    std::string fileName(std::to_string(hashedValue)); // Convert hash to hex string

    fs::path seedExportDirectory = mSeedsDirectory / std::to_string(dataModelPath.mClusterId);
    // Insert the command in the file at path "<seedsDirectory>/<clusterId>/<hashedValue>"
    if (!fs::exists(seedExportDirectory))
    {
        VerifyOrReturnError(!fs::create_directories(seedExportDirectory), CHIP_FUZZER_ERROR_SYSTEM_IO);
    }

    auto fd = fopen((seedExportDirectory / fileName).c_str(), "w");
    VerifyOrReturnError(nullptr != fd, CHIP_FUZZER_ERROR_SYSTEM_IO);

    fwrite(command, sizeof(char), strlen(command), fd);

    auto rv = fclose(fd);
    VerifyOrReturnError(EOF != rv, CHIP_FUZZER_ERROR_SYSTEM_IO);

    ChipLogProgress(chipTool, "Logged well-formed command: %s", command);

    return CHIP_NO_ERROR;
}

std::function<const char *(fs::path)> fuzz::ConvertStringToGenerationFunction(const char * key)
{
    if (std::string(key).compare("seed-only") == 0)
    {
        return fuzz::generation::GenerateCommandSeedOnly;
    }
    else
    {
        return nullptr;
    }
}
