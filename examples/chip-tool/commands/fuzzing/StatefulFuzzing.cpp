#include "StatefulFuzzing.h"

namespace fuzz = chip::fuzzing;

CHIP_ERROR fuzz::stateful::Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory,
                                Optional<fs::path> stateLogExportDirectory, fuzz::Fuzzer ** fuzzer)
{
    switch (type)
    {
    case AFL_PLUSPLUS:
        *fuzzer = new fuzz::stateful::AFLPlusPlus(seedsDirectory, strategy, stateLogExportDirectory);
        break;
    default:
        return CHIP_ERROR_NOT_IMPLEMENTED;
        break;
    }

    return CHIP_NO_ERROR;
} // namespace chip::fuzzing
