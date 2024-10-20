#pragma once
#include "../DeviceStateManager.h"
#include "../ForwardDeclarations.h"
#include <fstream>

namespace chip {
namespace fuzzing {
namespace generation {
class RuntimeGrammarManager
{
public:
    RuntimeGrammarManager(const chip::fuzzing::BasicInformation * nodeInfo, fs::path baseDir) :
        mBaseLexerPath("examples/chip-tool/commands/fuzzing/generation/CommandLexer.g4"),
        mBaseParserPath("examples/chip-tool/commands/fuzzing/generation/CommandParser.g4")
    {
        std::ostringstream filename(nodeInfo->vendorName, std::ios_base::ate);
        filename << std::hex << "_" << nodeInfo->vendorId << "_" << nodeInfo->productId << "_" << nodeInfo->hwVersion << "_"
                 << nodeInfo->swVersion << std::dec;
        if (!fs::exists(baseDir))
        {
            VerifyOrDie(fs::create_directories(baseDir));
        }
        mGrammarId                    = filename.str();
        fs::path mGrammarSubdirectory = baseDir / mGrammarId;
        if (!fs::exists(mGrammarSubdirectory))
        {
            VerifyOrDie(fs::create_directories(mGrammarSubdirectory));
        }
        mGeneratedLexerPath  = mGrammarSubdirectory / (mGrammarId + "_Lexer.g4");
        mGeneratedParserPath = mGrammarSubdirectory / (mGrammarId + "_Parser.g4");
        SetPythonExecutable();
        VerifyOrDieWithMsg(IsGrammarinatorInstalled(), chipFuzzer,
                           "Python package 'grammarinator' is required for fuzzer grammar generation.");
    };
    ~RuntimeGrammarManager() = default;

    std::string mGrammarId;

    void CreateGrammar(DeviceStateManager * deviceState, chip::NodeId node);
    void GenerateTestCases(fs::path outDir, size_t numCases, uint16_t maxDepth = 12);

private:
    fs::path mBaseLexerPath;
    fs::path mBaseParserPath;
    fs::path mGeneratedLexerPath;
    fs::path mGeneratedParserPath;
    std::string mPythonExecutable;
    std::string mEnvPrefix;

    std::string GetLexerName() { return mGeneratedLexerPath.stem().string(); }
    std::string GetParserName() { return mGeneratedParserPath.stem().string(); }
    void SetPythonExecutable();
    bool IsGrammarinatorInstalled();
};

} // namespace generation
} // namespace fuzzing
} // namespace chip
