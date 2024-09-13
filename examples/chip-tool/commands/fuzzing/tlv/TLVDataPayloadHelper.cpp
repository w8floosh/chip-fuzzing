#include "TLVDataPayloadHelper.h"

namespace fuzz = chip::fuzzing;
CHIP_ERROR
fuzz::TLV::TLVDataPayloadHelper::Decode(DecodedTLVElement<TLVType::kTLVType_Structure> & output)
{
    CHIP_ERROR err;
    while (CHIP_END_OF_TLV != (err = mPayloadReader.Next()))
    {
        // switch (mPayloadReader.GetType())
        // {
        // case TLVType::kTLVType_Structure:
        //     app::StructParser parser;
        //     parser.Init(mPayloadReader);
        //     break;
        // case TLVType::kTLVType_Array:
        //     break;
        // case TLVType::kTLVType_List:
        //     break;
        // case TLVType::kTLVType_UTF8String:
        //     break;
        // case TLVType::kTLVType_Boolean:
        //     break;
        // case TLVType::kTLVType_UnsignedInteger:
        //     break;
        // case TLVType::kTLVType_ByteString:
        //     break;
        // case TLVType::kTLVType_FloatingPointNumber:
        //     break;
        // case TLVType::kTLVType_NotSpecified:
        //     break;
        // case TLVType::kTLVType_UnknownContainer:
        //     break;
        // default:
        //     break;
        // }
    }
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::Encode(DecodedTLVElement<TLVType::kTLVType_Structure> & src)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::WriteToDeviceState(fuzz::TLV::DecodedTLVElement<TLVType::kTLVType_Structure> & src,
                                                               fuzz::DeviceStateManager & deviceStateManager)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::LoadClusterSnapshot(fs::path src, fuzz::ClusterState & state, bool fromJSON)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::LoadClusterSnapshot(fs::path src, chip::TLV::TLVWriter & writer, bool fromJSON)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::LoadClusterSnapshot(fs::path src, std::string & jsonStr, bool fromJSON)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::SaveClusterSnapshot(fs::path dst, fuzz::ClusterState & state, bool toJSON)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::SaveClusterSnapshot(fs::path dst, fuzz::ClusterState & state, std::string lastCommand,
                                                                bool toJSON)
{
    return CHIP_NO_ERROR;
}
CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::SaveClusterSnapshot(fs::path dst, fuzz::ClusterState & state,
                                                                std::vector<std::string> commandHistory, bool toJSON)
{
    return CHIP_NO_ERROR;
}

auto fuzz::TLV::TLVDataPayloadHelper::GetParser()
{
    // switch (mMessageType)
    // {
    // case chip::Protocols::InteractionModel::MsgType::StatusResponse:
    //     return std::make_unique<chip::app::StatusIB::Parser>();
    //     break;

    // case chip::Protocols::InteractionModel::MsgType::ReportData:
    //     return std::make_unique<chip::app::ReportData::Parser>();
    //     break;

    // case chip::Protocols::InteractionModel::MsgType::WriteResponse:
    //     return std::make_unique<chip::app::WriteResponse::Parser>();
    //     break;

    // case chip::Protocols::InteractionModel::MsgType::InvokeCommandResponse:
    //     return std::make_unique<chip::app::InvokeCommandResponse::Parser>();
    //     break;

    // default:
    //     return nullptr;
    // }
    return nullptr;
}
