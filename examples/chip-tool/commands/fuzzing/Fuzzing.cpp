#include "Fuzzing.h"
#include "Visitors.h"
#include "generation/Wrappers.cpp"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>

namespace fuzz = chip::fuzzing;
void fuzz::Fuzzer::AnalyzeCommandResponse(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path,
                                          const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(path.mEndpointId, path.mClusterId, path.mCommandId);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        TLV::DecodedTLVElementPrettyPrinter(output).Print();
        // TODO: To modify the local device state, we process the subscription response
        // TODO: [DISCLAIMER] We assume the request-response-subscription_response flow is synchronous (in this order)
    }

    // TODO: Parse the TLV data and call mOracle.Consume() on every attribute/path scanned
    // TODO: For each error, log a line showing command, error type and error description
    // mOracle->Consume(path, status, expectedStatus);
}

void fuzz::Fuzzer::AnalyzeReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                                     const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(path);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        TLV::DecodedTLVElementPrettyPrinter(output).Print();

        // TODO: Read the new value of the attribute and update the device state accordingly
        if (path.mClusterId == chip::app::Clusters::Descriptor::Id)
        {
            ProcessDescriptorClusterResponse(output, path, mCurrentDestination);
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
            // mOracle->Consume(path, attributeState, status);
        }
    }

    // TODO: Parse the TLV data and call mOracle.Consume() on every attribute/path scanned
    // TODO: For each error, log a line showing command, error type and error description
}

void fuzz::Fuzzer::AnalyzeReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
                                     const chip::app::StatusIB * status, chip::app::StatusIB expectedStatus)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(eventHeader);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        output->content = ContainerType();
        helper.Decode(output);
        TLV::DecodedTLVElementPrettyPrinter(output).Print();
    }

    // TODO: Parse the TLV data and call mOracle.Consume() on every attribute/path scanned
    // TODO: For each error, log a line showing command, error type and error description
    // mOracle->Consume(*status, expectedStatus);
}

void fuzz::Fuzzer::AnalyzeReportError(const chip::app::ConcreteDataAttributePath & path, const chip::app::StatusIB & status)
{
    auto & attributeState =
        mDeviceStateManager.GetAttributeState(mCurrentDestination, path.mEndpointId, path.mClusterId, path.mAttributeId);
    if (attributeState.IsReadable())
        attributeState.ToggleBlockReads();
}
void fuzz::Fuzzer::AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                                       CHIP_ERROR expectedError)
{}

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
        VerifyOrReturnError(!fs::create_directories(seedExportDirectory), CHIP_FUZZER_FILESYSTEM_ERROR);
    }

    auto fd = fopen((seedExportDirectory / fileName).c_str(), "w");
    VerifyOrReturnError(nullptr != fd, CHIP_FUZZER_FILESYSTEM_ERROR);

    fwrite(command, sizeof(char), strlen(command), fd);

    auto rv = fclose(fd);
    VerifyOrReturnError(EOF != rv, CHIP_FUZZER_FILESYSTEM_ERROR);

    ChipLogProgress(chipTool, "Logged well-formed command: %s", command);

    return CHIP_NO_ERROR;
}

void fuzz::Fuzzer::ProcessDescriptorClusterResponse(std::shared_ptr<TLV::DecodedTLVElement> decoded,
                                                    const chip::app::ConcreteDataAttributePath & path, NodeId node)
{
    switch (path.mAttributeId)
    {
    case chip::app::Clusters::Descriptor::Attributes::PartsList::Id: {
        Visitors::TLV::ProcessDescriptorClusterResponse<EndpointId>(std::move(decoded), path, node);
        break;
    }
    case chip::app::Clusters::Descriptor::Attributes::DeviceTypeList::Id:
    case chip::app::Clusters::Descriptor::Attributes::ServerList::Id: {
        // This case also applies to the DeviceTypeId: both types are uint32_t
        Visitors::TLV::ProcessDescriptorClusterResponse<ClusterId>(std::move(decoded), path, node);
        break;
    }
    }
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
