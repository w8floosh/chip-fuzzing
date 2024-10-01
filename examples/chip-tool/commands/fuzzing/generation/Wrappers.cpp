#include "../ForwardDeclarations.h"
#include <fstream>
#include <random>

namespace fs = std::filesystem;

namespace chip {
namespace fuzzing {
namespace generation {
const char * GenerateCommandSeedOnly(fs::path seedsDir)
{
    std::vector<std::string> files;

    VerifyOrDie(std::filesystem::exists(seedsDir));
    // Read all file names from the seed directory
    for (const auto & entry : std::filesystem::directory_iterator(seedsDir))
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

    std::string randomFile = files[static_cast<size_t>(dis(gen))];

    // Read the first line from the random file
    std::ifstream inputFile(randomFile);
    std::string firstLine;
    if (std::getline(inputFile, firstLine))
    {
        char * command = new char[firstLine.length() + 1];
        strncpy(command, firstLine.c_str(), firstLine.length() + 1);
        return command;
    }
    // Return nullptr if the file is empty or cannot be read
    return nullptr;
};

} // namespace generation
} // namespace fuzzing
} // namespace chip
