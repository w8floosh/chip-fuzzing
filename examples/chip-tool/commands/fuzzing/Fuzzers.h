#pragma once
#include "Fuzzing.h"

namespace chip {
namespace fuzzing {
namespace wrappers {
class AFLPlusPlus : public Fuzzer
{
public:
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy) : Fuzzer(seedsDirectory, strategy) {};
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy, fs::path outputDirectory) :
        Fuzzer(seedsDirectory, strategy, outputDirectory) {};

    ~AFLPlusPlus() {};

    const char * GenerateCommand() override;
};

class SeedOnly : public Fuzzer
{
public:
    SeedOnly(fs::path seedsDirectory) : Fuzzer(seedsDirectory, NONE) {};
    SeedOnly(fs::path seedsDirectory, fs::path outputDirectory) : Fuzzer(seedsDirectory, NONE, outputDirectory) {};

    ~SeedOnly() {};

    const char * GenerateCommand() override;
};

} // namespace wrappers
} // namespace fuzzing
} // namespace chip
