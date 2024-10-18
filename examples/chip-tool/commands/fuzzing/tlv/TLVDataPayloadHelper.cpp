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
        output->content = NullOptional;
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
            ReturnErrorOnFailure(Decode(newElement));
            mPayloadReader.ExitContainer(outerContainer);
        }
        else
        {
            // Base case of recursion
            ReturnErrorOnFailure(DecodePrimitive(type, bytes, newElement));
        }
        ReturnErrorOnFailure(PushToContainer(std::move(newElement), output));
        err = mPayloadReader.Next();
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::Encode(std::shared_ptr<DecodedTLVElement> src)
{
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::WriteToDeviceState(std::shared_ptr<DecodedTLVElement> && src,
                                                               AttributeState & attributeState)
{
    // src is ALWAYS a structure element. The first element of the structure is the actual value
    VerifyOrReturnError(std::holds_alternative<ContainerType>(src->content), CHIP_ERROR_INTERNAL);
    auto container = std::move(src);
    auto element   = std::get<ContainerType>(container->content).at(0);
    VerifyOrReturnError(element != nullptr, CHIP_ERROR_INTERNAL);
    if (std::holds_alternative<std::monostate>(attributeState.ReadCurrent()))
    {
        ReturnErrorOnFailure(
            attributeState.LazyInitialize(container->type, container->length, container->quality, std::move(element->content)));
    }
    else
    {
        ReturnErrorOnFailure(attributeState.Write(std::move(element->content)));
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR fuzz::TLV::TLVDataPayloadHelper::PushToContainer(std::shared_ptr<DecodedTLVElement> && element,
                                                            std::shared_ptr<DecodedTLVElement> dst)
{
    return Visitors::TLV::PushToContainer(std::move(element), dst);
}

void fuzz::TLV::TLVDataPayloadHelper::PrettyPrint()
{
    chip::TLV::TLVReader printBuffer;
    printBuffer.Init(mPayloadReader);
    chip::TLV::Debug::Dump(printBuffer, TLVPrettyPrinter);
}

void fuzz::TLV::TLVDataPayloadHelper::PrintRaw(const uint8_t * data, size_t length)
{
    chip::TLV::TLVReader reader;
    reader.Init(data, length);
    chip::TLV::Debug::Dump(reader, TLVPrettyPrinter);
}
