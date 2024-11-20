#include "InputGenerator.h"
#include "../DeviceStateTracker.h"
#include "../Visitors.h"
#include "../tlv/DecodedTLVElement.h"
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <json/json.h>
#include <regex>
namespace {
uint64_t hexToUnsignedInt(const std::string & hexStr)
{
    uint64_t value;
    std::stringstream ss;
    ss << std::hex << hexStr;
    ss >> value;
    return value;
}

// Convert hex string to signed integer
int64_t hexToSignedInt(const std::string & hexStr)
{
    uint64_t unsignedValue = hexToUnsignedInt(hexStr);
    // Interpret the value as a signed integer based on its length
    int64_t signedValue = static_cast<int64_t>(unsignedValue);
    return signedValue;
}

// Convert hex string to float
float hexToFloat(const std::string & hexStr)
{
    uint32_t intValue = static_cast<uint32_t>(hexToUnsignedInt(hexStr));
    float floatValue;
    std::memcpy(&floatValue, &intValue, sizeof(floatValue)); // Bitwise conversion
    return floatValue;
}

// Convert hex string to double
double hexToDouble(const std::string & hexStr)
{
    uint64_t intValue = hexToUnsignedInt(hexStr);
    double doubleValue;
    std::memcpy(&doubleValue, &intValue, sizeof(doubleValue)); // Bitwise conversion
    return doubleValue;
}

// Function to scan and convert hex values in JSON string
std::string convertHexToDecimal(std::string json)
{
    // Define the regular expression pattern for matching the values
    std::regex pattern(R"(\"(s:|f:|d:)?(0x[0-9a-fA-F]+)\")");
    std::smatch match;

    std::string result;
    std::string::const_iterator searchStart(json.cbegin());

    while (std::regex_search(searchStart, json.cend(), match, pattern))
    {
        // Append the part of the JSON before the match
        result += match.prefix();

        // Extract the matched components
        std::string prefix   = match[1]; // "s:", "f:", "d:", or empty
        std::string hexValue = match[2]; // Hex number

        // Remove "0x" prefix from the hex number for easier conversion
        hexValue = hexValue.substr(2);

        // Convert based on the prefix
        std::ostringstream convertedValue;
        convertedValue << prefix;
        if (prefix == "s:")
        {
            convertedValue << hexToSignedInt(hexValue) << "\"";
        }
        else if (prefix == "f:")
        {
            convertedValue << std::fixed << hexToFloat(hexValue) << std::dec << "\"";
        }
        else if (prefix == "d:")
        {
            convertedValue << std::fixed << hexToDouble(hexValue) << std::dec << "\"";
        }
        else
        {
            convertedValue << hexToUnsignedInt(hexValue) << "\"";
        }

        // Append the converted value to the result
        result += "\"" + convertedValue.str();

        // Move searchStart forward to continue searching the rest of the string
        searchStart = match.suffix().first;
    }

    // Append the remaining part of the JSON string
    result += std::string(searchStart, json.cend());

    return result;
}
} // namespace
namespace gen = chip::fuzzing::generation;
void gen::InputGenerator::CreateGrammar(DeviceStateTracker * deviceState, chip::NodeId node)
{
    VerifyOrReturn(!fs::exists(mGeneratedLexerPath) && !fs::exists(mGeneratedParserPath));

    std::ifstream baseLexerFile(mBaseLexerPath);
    std::ifstream baseParserFile(mBaseParserPath);
    VerifyOrDieWithMsg(baseLexerFile.is_open(), chipFuzzer, "Failed to open base lexer file.");
    VerifyOrDieWithMsg(baseParserFile.is_open(), chipFuzzer, "Failed to open base parser file.");

    std::ofstream generatedLexerFile(mGeneratedLexerPath);
    VerifyOrDieWithMsg(generatedLexerFile.is_open(), chipFuzzer, "Failed to create lexer file.");
    std::string line;
    while (std::getline(baseLexerFile, line))
    {
        if (line.find("CommandLexer") != std::string::npos)
        {
            line.replace(line.find("CommandLexer"), std::string("CommandLexer").length(), GetLexerName());
        }
        generatedLexerFile << line << "\n";
    }

    std::ostringstream commandToken("CMDPATH: ", std::ios_base::ate);

    auto endpoints          = *deviceState->List(node);
    size_t scannedEndpoints = 0;
    for (auto & endpoint : endpoints)
    {
        if (!endpoint.second.clusters.size())
            continue;
        commandToken << "E" << endpoint.first;
        std::ostringstream endpointToken("E" + std::to_string(endpoint.first) + ": ", std::ios_base::ate);
        endpointToken << "'" << std::to_string(endpoint.first) << "' SPACE (";
        size_t scannedClusters = 0;
        for (auto & cluster : endpoint.second.clusters)
        {
            auto attr = cluster.second.attributes.find(chip::app::Clusters::Globals::Attributes::AcceptedCommandList::Id);
            VerifyOrDie(attr != cluster.second.attributes.end());
            auto commandList = std::get<ContainerType>(attr->second.ReadCurrent());
            // Creating a token when the command list is empty would generate a token "'x' SPACE ()", which would be invalid.
            if (!commandList.size())
            {
                scannedClusters++;
                continue;
            }

            endpointToken << "E" << endpoint.first << "CL" << cluster.first;
            std::ostringstream clusterToken("E" + std::to_string(endpoint.first), std::ios_base::ate);
            clusterToken << "CL" << cluster.first << ": '" << std::to_string(cluster.first) << "' SPACE (";
            for (size_t i = 0; i < commandList.size(); i++)
            {
                auto commandId = chip::fuzzing::Visitors::TLV::ConvertToIdType<uint32_t>(commandList[i]);
                clusterToken << "'" << commandId << "'";
                if (i != commandList.size() - 1)
                {
                    clusterToken << "|";
                }
            }
            clusterToken << ");\n";
            generatedLexerFile << clusterToken.str();

            // TODO: Simplify this by popping the last '|' back
            if (scannedClusters != endpoint.second.clusters.size() - 1)
            {
                endpointToken << "|";
            }
            scannedClusters++;
        }
        endpointToken << ");\n";
        generatedLexerFile << endpointToken.str();

        // TODO: Simplify this by popping the last '|' back
        if (scannedEndpoints != endpoints.size() - 1)
        {
            commandToken << "|";
        }
        scannedEndpoints++;
    }
    commandToken << ";\n";
    generatedLexerFile << commandToken.str();

    std::ofstream generatedParserFile(mGeneratedParserPath);
    VerifyOrDieWithMsg(generatedParserFile.is_open(), chipFuzzer, "Failed to create parser file.");

    while (std::getline(baseParserFile, line))
    {
        if (line.find("CommandLexer") != std::string::npos)
        {
            line.replace(line.find("CommandLexer"), std::string("CommandLexer").length(), GetLexerName());
        }
        else if (line.find("CommandParser") != std::string::npos)
        {
            line.replace(line.find("CommandParser"), std::string("CommandParser").length(), GetParserName());
        }
        else if (line.find("}") != std::string::npos)
        {
            line = "}\n\nargs: CMDPATH SPACE payload EOF;";
        }
        generatedParserFile << line << "\n";
    }

    baseLexerFile.close();
    baseParserFile.close();
    generatedLexerFile.close();
    generatedParserFile.close();

    VerifyOrDieWithMsg(!generatedLexerFile.is_open(), chipFuzzer, "Lexer file was in an incorrect state.");
    VerifyOrDieWithMsg(!generatedParserFile.is_open(), chipFuzzer, "Parser file was in an incorrect state.");
    ChipLogProgress(chipFuzzer, "Grammar files generated successfully: GrammarID: %s.", mGrammarId.c_str());

    std::ostringstream processCommand(mPythonExecutable, std::ios_base::ate);
    std::string grammarinatorProcessFile = std::string(mEnvPrefix + "/bin/grammarinator-process");
    std::string baseLexerFilename        = mBaseLexerPath.string();
    std::string baseParserFilename       = mBaseParserPath.string();
    std::string generatedLexerFilename   = mGeneratedLexerPath.string();
    std::string generatedParserFilename  = mGeneratedParserPath.string();

    processCommand << " " << grammarinatorProcessFile << " " << generatedLexerFilename << " " << generatedParserFilename << " -o "
                   << mGeneratedLexerPath.parent_path().string() << " --no-actions";

    VerifyOrDieWithMsg(std::system(processCommand.str().c_str()) == 0, chipFuzzer, "Failed to process grammar files.");
    ChipLogProgress(chipFuzzer, "Grammar files processed successfully.");
};

void gen::InputGenerator::SetPythonExecutable()
{
    VerifyOrDieWithMsg(std::system("python --version > /dev/null 2>&1") == 0, chipFuzzer, "Python is required to run the fuzzer.");
    const char * condaPrefix = std::getenv("CONDA_PREFIX");
    std::string execPath     = "python";
    if (condaPrefix)
    {
        execPath = std::string(condaPrefix) + "/bin/python";
        ChipLogProgress(chipFuzzer, "Conda environment detected. Using: %s", execPath.c_str());
        mEnvPrefix = std::string(condaPrefix);
    }
    else
    {
        ChipLogProgress(chipFuzzer, "Using system Python: %s", execPath.c_str());
        mEnvPrefix = "$PATH";
    }
    mPythonExecutable = execPath;
};

bool gen::InputGenerator::IsGrammarinatorInstalled()
{
    std::string command = mPythonExecutable + " -c \"import grammarinator\"";
    return std::system(command.c_str()) == 0;
}

void gen::InputGenerator::GenerateTestCases(fs::path outFile, size_t numCases, uint16_t maxDepth)
{
    VerifyOrDieWithMsg(std::filesystem::exists(mGeneratedLexerPath), chipFuzzer, "Lexer file not found.");
    VerifyOrDieWithMsg(std::filesystem::exists(mGeneratedParserPath), chipFuzzer, "Parser file not found.");

    if (!fs::exists(outFile.parent_path()))
    {
        VerifyOrDie(fs::create_directories(outFile.parent_path()));
    }

    std::ostringstream command("PYTHONUNBUFFERED=1 " + mPythonExecutable, std::ios_base::ate);

    std::string grammarinatorGenerateFile = std::string(mEnvPrefix + "/bin/grammarinator-generate");
    std::string baseLexerFilename         = mBaseLexerPath.string();
    std::string generatedLexerFilename    = mGeneratedLexerPath.string();
    std::string generatorClassName        = std::string(mGeneratedLexerPath.parent_path().filename().string() + "_Generator." +
                                                        mGeneratedLexerPath.parent_path().filename().string() + "_Generator");
    command << " " << grammarinatorGenerateFile << " " << generatorClassName << " -d " << maxDepth << " -n " << numCases
            << " -j 1 --stdout --sys-path " << mGeneratedLexerPath.parent_path().string() << " > " << outFile.string();

    ChipLogProgress(chipFuzzer, "Generating test cases...");
    VerifyOrDieWithMsg(std::system(command.str().c_str()) == 0, chipFuzzer, "Failed to generate test cases.");
    ChipLogProgress(chipFuzzer, "Generated %zu test cases.", numCases);
}

std::string gen::InputGenerator::ParseTestCase(chip::NodeId node, std::string testCase)
{
    Json::Value root;
    Json::CharReaderBuilder reader;
    std::string errs;

    std::string endpoint, cluster, command;
    std::istringstream iss(testCase);

    // Skip the first three tokens (endpoint, cluster, command)
    iss >> endpoint >> cluster >> command;

    if (!Json::parseFromStream(reader, iss, &root, &errs))
    {
        std::cerr << "Error parsing JSON: " << errs << std::endl;
        return "";
    }

    // Serialize back to string without duplicate keys
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";
    std::string json      = Json::writeString(writer, root);
    std::string payload   = convertHexToDecimal(json);

    return cluster + " " + command + " " + payload + " " + std::to_string(node) + " " + endpoint;
}
