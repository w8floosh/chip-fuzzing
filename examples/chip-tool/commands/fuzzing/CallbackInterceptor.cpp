#include "CallbackInterceptor.h"
#include "Fuzzer.h"
#include "Oracle.h"
#include "tlv/DecodedTLVElement.h"
#include "tlv/TLVDataPayloadHelper.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/InteractionModelEngine.h>
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
    }
}

void fuzz::CallbackInterceptor::ProcessReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                                                  const chip::app::StatusIB & status)
{
    auto fuzzer = fuzz::Fuzzer::GetInstance();
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
                Visitors::TLV::ProcessDescriptorClusterResponse<EndpointId>(output, path, fuzzer->CurrentDestination());
                break;
            }
            case chip::app::Clusters::Descriptor::Attributes::DeviceTypeList::Id:
            case chip::app::Clusters::Descriptor::Attributes::ServerList::Id: {
                // This case also applies to the DeviceTypeId: both types are uint32_t
                Visitors::TLV::ProcessDescriptorClusterResponse<ClusterId>(output, path, fuzzer->CurrentDestination());
                break;
            }
            }
        }
        else if (path.mClusterId == chip::app::Clusters::BasicInformation::Id)
        {
            Visitors::TLV::ProcessBasicInformationClusterResponse(output, path, fuzzer->CurrentDestination());
        }
        else
        {
            auto & attributeState = fuzzer->GetDeviceStateTracker()->GetAttributeState(
                fuzzer->CurrentDestination(), path.mEndpointId, path.mClusterId, path.mAttributeId);
            helper.WriteToDeviceState(std::move(output), attributeState);
        }
    }
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
}

void fuzz::CallbackInterceptor::AnalyzeReportError(const chip::app::ConcreteDataAttributePath & path,
                                                   const chip::app::StatusIB & status)
{
    auto fuzzer           = fuzz::Fuzzer::GetInstance();
    auto & attributeState = fuzzer->GetDeviceStateTracker()->GetAttributeState(fuzzer->CurrentDestination(), path.mEndpointId,
                                                                               path.mClusterId, path.mAttributeId);
    if (attributeState.IsReadable())
        attributeState.ToggleBlockReads();
}

void fuzz::CallbackInterceptor::AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                                                    CHIP_ERROR expectedError)
{}
