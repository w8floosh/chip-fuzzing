#include "Fuzzing.h"

namespace fuzz = chip::fuzzing;

namespace {

std::unordered_map<std::string, fuzz::FuzzerType> fuzzerTypeMap           = { { "afl++", fuzz::FuzzerType::AFL_PLUSPLUS } };
std::unordered_map<std::string, fuzz::FuzzingStrategy> fuzzingStrategyMap = {};

template <typename T>
T * GetMapElementFromKeyEnum(const std::unordered_map<std::string, T> & map, const char * key)
{
    VerifyOrReturnValue(std::is_enum<T>::value, nullptr);

    auto found = map.find(std::string(key));
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

fuzz::FuzzerType * fuzz::ConvertStringToFuzzerType(char * const & key)
{
    return GetMapElementFromKeyEnum<fuzz::FuzzerType>(fuzzerTypeMap, key);
}

fuzz::FuzzingStrategy * fuzz::ConvertStringToFuzzingStrategy(char * const & key)
{
    return GetMapElementFromKeyEnum<fuzz::FuzzingStrategy>(fuzzingStrategyMap, key);
}
