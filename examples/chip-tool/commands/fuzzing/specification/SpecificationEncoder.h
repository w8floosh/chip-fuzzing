#pragma once
#include "../ForwardDeclarations.h"
#include "../Utils.h"
#include <map>
class FuzzingCommand;

namespace chip {
namespace fuzzing {
namespace specification {

struct CommandSpecification
{
    std::map<uint8_t, const std::pair<chip::TLV::TLVType, uint8_t>> requiredCommandFields;
    std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> inferredPossibleErrors = { CHIP_NO_ERROR };
    chip::Optional<std::array<int64_t, 2>> constraintLimits                    = chip::NullOptional;
    // TODO: std::unordered_map<IMStatus, Json::Value> malformedPayloadExamples;
};

struct AttributeSpecification
{
    bool nullable                                           = false;
    TLV::TLVType type                                       = TLV::TLVType::kTLVType_NotSpecified;
    chip::Optional<std::array<int64_t, 2>> constraintLimits = chip::NullOptional;
    std::string acl                                         = "rw";
    // TODO: std::string conformance;
};
class SpecificationEncoder
{
public:
    SpecificationEncoder() = delete;
    SpecificationEncoder(FuzzingCommand * handler) : mCommandHandler(handler) {}
    CHIP_ERROR
    TryInferCommandSpecification(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command,
                                 fs::path dependencyTestFile, bool enableTCP = false);
    CHIP_ERROR InferAttributeSpecification(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute)
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }
    CHIP_ERROR InferEventSpecification(chip::EndpointId endpoint, chip::ClusterId cluster, chip::EventId event)
    {
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }
    std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & GetExpectedErrors(chip::app::ConcreteCommandPath comPath)
    {
        return mCommandSpecifications[comPath].inferredPossibleErrors;
    }
    std::map<uint8_t, const std::pair<chip::TLV::TLVType, uint8_t>> & GetCommandFields(chip::app::ConcreteCommandPath comPath)
    {
        return mCommandSpecifications[comPath].requiredCommandFields;
    }
    chip::Optional<std::array<int64_t, 2>> & GetConstraintLimits(chip::app::ConcreteCommandPath comPath)
    {
        return mCommandSpecifications[comPath].constraintLimits;
    }

private:
    FuzzingCommand * mCommandHandler;
    std::unordered_map<chip::app::ConcreteCommandPath, CommandSpecification, utils::MapKeyHasher> mCommandSpecifications;
    std::unordered_map<chip::app::ConcreteDataAttributePath, chip::NullOptionalType, utils::MapKeyHasher> mAttributeSpecifications;
    CHIP_ERROR ShuffleClusterState(fs::path dependencyTestFilePath, chip::app::ConcreteCommandPath comPath);
};
} // namespace specification
} // namespace fuzzing
} // namespace chip
