#include "Fuzzers.h"
#include <fstream>
#include <random>
namespace fuzzers = chip::fuzzing::wrappers;

const char * fuzzers::AFLPlusPlus::GenerateCommand()
{
    return nullptr;
}
const char * fuzzers::SeedOnly::GenerateCommand()
{
    std::vector<std::string> files;

    VerifyOrDie(std::filesystem::exists(mSeedsDirectory));
    // Read all file names from the seed directory
    for (const auto & entry : std::filesystem::directory_iterator(mSeedsDirectory))
    {
        if (entry.is_regular_file())
        {
            files.push_back(entry.path().string());
        }
    }

    // Select a random file from the list
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int) files.size() - 1);
    std::string randomFile = files[dis(gen)];

    // Read the first line from the random file
    std::ifstream inputFile(randomFile);
    std::string firstLine;
    if (std::getline(inputFile, firstLine))
    {
        return firstLine.c_str();
    }
    // Return nullptr if the file is empty or cannot be read
    return nullptr;
}
