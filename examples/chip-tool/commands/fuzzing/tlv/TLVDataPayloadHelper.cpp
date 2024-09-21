#include "TLVDataPayloadHelper.h"
#include <app/tests/integration/common.cpp>

namespace fuzz = chip::fuzzing;

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::DecodePrimitive(TLVType dstType, uint8_t dstBytes,
                                                            std::shared_ptr<DecodedTLVElement> output)
{
    VerifyOrReturnError(!output->IsContainer(), CHIP_ERROR_WRONG_TLV_TYPE);
    switch (dstType)
    {
    case TLVType::kTLVType_Boolean: {
        bool v;
        mPayloadReader.Get(v);
        output->content = v;
        break;
    }
    case TLVType::kTLVType_Null: {
        output->content = std::nullopt;
        break;
    }
    case TLVType::kTLVType_SignedInteger: {
        switch (dstBytes)
        {
        case 1: {
            int8_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 2: {
            int16_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 4: {
            int32_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 8: {
            int64_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        default:
            return CHIP_ERROR_WRONG_TLV_TYPE;
        }
        break;
    }
    case TLVType::kTLVType_UnsignedInteger: {
        switch (dstBytes)
        {
        case 1: {
            uint8_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 2: {
            uint16_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 4: {
            uint32_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 8: {
            uint64_t v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        default:
            return CHIP_ERROR_WRONG_TLV_TYPE;
        }
        break;
    }
    case TLVType::kTLVType_FloatingPointNumber: {
        switch (dstBytes)
        {
        case 4: {
            float v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        case 8: {
            double v;
            mPayloadReader.Get(v);
            output->content = v;
            break;
        }
        default:
            return CHIP_ERROR_WRONG_TLV_TYPE;
        }
        break;
    }
    case TLVType::kTLVType_UTF8String:
    case TLVType::kTLVType_ByteString: {
        std::vector<char> buffer(mPayloadReader.GetLength() + 1);
        mPayloadReader.GetString(buffer.data(), buffer.size());
        output->content = std::string(buffer.data(), strlen(buffer.data()));
        break;
    }
    default:
        return CHIP_ERROR_WRONG_TLV_TYPE;
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::Decode(std::shared_ptr<DecodedTLVElement> output)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    if (mPayloadReader.GetType() == TLVType::kTLVType_NotSpecified)
    {
        err = mPayloadReader.Next();
    }
    while (CHIP_END_OF_TLV != err)
    {
        TLVType type = mPayloadReader.GetType();
        VerifyOrReturnError((type != TLVType::kTLVType_UnknownContainer) || (type != TLVType::kTLVType_NotSpecified),
                            CHIP_ERROR_INVALID_TLV_ELEMENT);
        uint16_t cbyte = mPayloadReader.GetControlByte();
        TLVTag tag     = ExtractTagFromControlByte(cbyte);
        uint8_t bytes  = ExtractSizeFromControlByte(type, cbyte);
        AttributeQualityEnum quality =
            type == TLVType::kTLVType_Null ? AttributeQualityEnum::kOptional : AttributeQualityEnum::kMandatory;

        auto newElement = DecodedTLVElement::Create(type, bytes, tag, quality);
        VerifyOrReturnError(newElement != nullptr, CHIP_ERROR_INVALID_TLV_ELEMENT);

        if (type == TLVType::kTLVType_Structure || type == TLVType::kTLVType_Array || type == TLVType::kTLVType_List)
        {
            TLVType outerContainer;
            mPayloadReader.EnterContainer(outerContainer);
            newElement->content = ContainerType();
            err                 = Decode(newElement);
            VerifyOrReturnError(err == CHIP_NO_ERROR, err);
            mPayloadReader.ExitContainer(outerContainer);
        }
        else
        {
            // Base case of recursion
            err = DecodePrimitive(type, bytes, newElement);
        }
        VerifyOrReturnError(err == CHIP_NO_ERROR, err);
        err = PushToContainer(std::move(newElement), output);
        VerifyOrReturnError(err == CHIP_NO_ERROR, err);
        err = mPayloadReader.Next();
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::Encode(std::shared_ptr<DecodedTLVElement> src)
{
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::WriteToDeviceState(std::shared_ptr<DecodedTLVElement> src,
                                                               AttributeState & attributeState)
{

    /**
     * DecodedTLVElement and AttributeState have different representations of the underlying value.
     * We need to convert the DecodedTLVElement to the standard type before writing to the device state.
     */
    if (attributeState.ReadCurrent() == nullptr)
    {
        ReturnErrorOnFailure(attributeState.LazyInitialize(src->type, src->length, src->quality, src->content));
    }
    else
    {
        ReturnErrorOnFailure(attributeState.Write(src->content));
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::PushToContainer(std::shared_ptr<DecodedTLVElement> element,
                                                            std::shared_ptr<DecodedTLVElement> dst)
{
    return std::visit(
        [&](auto & container) -> CHIP_ERROR {
            using T = std::decay_t<decltype(container)>;
            if constexpr (std::is_same_v<T, ContainerType>)
            {
                container.push_back(std::move(element));
                return CHIP_NO_ERROR;
            }
            else
                return CHIP_ERROR_WRONG_TLV_TYPE;
        },
        dst->content);
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

void fuzz::TLV::TLVDataPayloadHelper::PrettyPrint()
{
    chip::TLV::TLVReader printBuffer;
    printBuffer.Init(mPayloadReader);
    chip::TLV::Debug::Dump(printBuffer, TLVPrettyPrinter);
}
