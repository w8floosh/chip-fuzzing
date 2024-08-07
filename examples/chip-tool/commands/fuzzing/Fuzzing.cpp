#include "Fuzzing.h"

namespace fuzz = chip::fuzzing;

namespace {

std::unordered_map<std::string, fuzz::FuzzerType> fuzzerTypeMap           = { { "afl++", fuzz::FuzzerType::AFL_PLUSPLUS } };
std::unordered_map<std::string, fuzz::FuzzingStrategy> fuzzingStrategyMap = {};

template <typename T>
T const * GetMapElementFromKeyEnum(const std::unordered_map<std::string, T> & map, const char * key)
{
    VerifyOrReturnValue(std::is_enum<T>::value, nullptr);

    auto found = map.find(std::string(key)) const;
    VerifyOrReturnValue(found != map.end(), nullptr);

    return &(found->second);
}
} // namespace

CHIP_ERROR fuzz::Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory, Fuzzer ** fuzzer)
{
    switch (type)
    {
    case AFL_PLUSPLUS:
        *fuzzer = new AFLPlusPlus(seedsDirectory, strategy);
        break;
    default:
        return CHIP_ERROR_NOT_IMPLEMENTED;
        break;
    }

    return CHIP_NO_ERROR;
};

CHIP_ERROR fuzz::Fuzzer::InitNodeState(NodeId id, const std::any * const & nodeData)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}
fuzz::FuzzerType const * fuzz::ConvertStringToFuzzerType(char * const & key)
{
    return GetMapElementFromKeyEnum<fuzz::FuzzerType>(fuzzerTypeMap, key);
}

fuzz::FuzzingStrategy const * fuzz::ConvertStringToFuzzingStrategy(char * const & key)
{
    return GetMapElementFromKeyEnum<fuzz::FuzzingStrategy>(fuzzingStrategyMap, key);
}
