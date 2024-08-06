#pragma once
#include "Fuzzing.h"

namespace fuzz = chip::fuzzing;

namespace {
template <class T>
T * GetMapElementFromKeyEnum(std::unordered_map<std::string, T> map, const char * key)
{
    if (key == nullptr)
    {
        return nullptr;
    }
    std::unordered_map<std::string, T>::iterator found = map.find(std::string(key));
    if (found == map.end())
    {
        return nullptr;
    }
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

fuzz::FuzzerType * fuzz::ConvertStringToFuzzerType(const char * key)
{
    return GetMapElementFromKeyEnum<FuzzerType>(fuzzerTypeMap, key);
}

fuzz::FuzzingStrategy * fuzz::ConvertStringToFuzzingStrategy(const char * key)
{
    return GetMapElementFromKeyEnum<FuzzingStrategy>(fuzzingStrategyMap, key);
}
