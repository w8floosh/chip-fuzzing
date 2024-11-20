#pragma once
#include "../DeviceStateTracker.h"
#include "../ForwardDeclarations.h"
#include <fstream>

namespace chip {
namespace fuzzing {
namespace generation {

class InputGenerator
{
public:
    InputGenerator(const chip::fuzzing::BasicInformation * nodeInfo, fs::path baseDir) :
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
        mGrammarId      = filename.str();
        mTargetDataPath = baseDir / mGrammarId;
        if (!fs::exists(mTargetDataPath))
        {
            VerifyOrDie(fs::create_directories(mTargetDataPath));
        }

        mGeneratedLexerPath  = mTargetDataPath / (mGrammarId + "_Lexer.g4");
        mGeneratedParserPath = mTargetDataPath / (mGrammarId + "_Parser.g4");
        SetPythonExecutable();
        VerifyOrDieWithMsg(IsGrammarinatorInstalled(), chipFuzzer,
                           "Python package 'grammarinator' is required for fuzzer grammar generation.");
    };
    ~InputGenerator() { fs::remove_all(mTargetDataPath / "tmp"); };

    std::string mGrammarId;

    void CreateGrammar(DeviceStateTracker * deviceState, chip::NodeId node);
    void GenerateTestCases(fs::path outDir, size_t numCases, uint16_t maxDepth = 32);
    // Removes duplicate keys from the test case payload and converts all keys from hex to decimal.
    static std::string ParseTestCase(chip::NodeId node, std::string testCase);

private:
    fs::path mBaseLexerPath;
    fs::path mBaseParserPath;
    fs::path mGeneratedLexerPath;
    fs::path mGeneratedParserPath;
    fs::path mTargetDataPath;
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
