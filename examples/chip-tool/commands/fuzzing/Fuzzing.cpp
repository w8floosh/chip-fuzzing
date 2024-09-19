#include "Fuzzing.h"
#include "generation/Wrappers.cpp"

namespace fuzz = chip::fuzzing;
void fuzz::Fuzzer::AnalyzeCommandResponse(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path,
                                          const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(path.mEndpointId, path.mClusterId, path.mCommandId);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        helper.Decode(output);
        output->Print();
    }

    // TODO: Parse the TLV data and call mOracle.Consume() on every attribute/path scanned
    // TODO: For each error, log a line showing command, error type and error description
    mOracle->Consume(status, expectedStatus);
}

void fuzz::Fuzzer::AnalyzeReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                                     const chip::app::StatusIB & status, chip::app::StatusIB expectedStatus)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(path);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        helper.Decode(output);
        output->Print();
    }

    // TODO: Parse the TLV data and call mOracle.Consume() on every attribute/path scanned
    // TODO: For each error, log a line showing command, error type and error description
    mOracle->Consume(status, expectedStatus);
}

void fuzz::Fuzzer::AnalyzeReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
                                     const chip::app::StatusIB * status, chip::app::StatusIB expectedStatus)
{
    if (data != nullptr)
    {
        TLV::TLVDataPayloadHelper helper(data);
        helper.Print(eventHeader);
        std::shared_ptr<TLV::DecodedTLVElement> output = TLV::DecodedTLVElement::Create(TLVType::kTLVType_Structure);
        VerifyOrDie(output != nullptr);
        helper.Decode(output);
        output->Print();

        // TODO: Add saving cluster snapshot to file on a certain condition
    }

    // TODO: Parse the TLV data and call mOracle.Consume() on every attribute/path scanned
    // TODO: For each error, log a line showing command, error type and error description
    mOracle->Consume(*status, expectedStatus);
}

void fuzz::Fuzzer::AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                                       CHIP_ERROR expectedError)
{}

CHIP_ERROR fuzz::Fuzzer::ExportSeedToFile(const char * command, const chip::app::ConcreteClusterPath & dataModelPath)
{
    namespace fs = std::filesystem;
    auto now     = std::chrono::system_clock::now();
    auto now_ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    // Create seed hash from current timestamp
    std::hash<std::string> hasher;
    size_t hashedValue = hasher(std::to_string(now_ms.count()));

    std::string fileName(std::to_string(hashedValue)); // Convert hash to hex string

    fs::path seedExportDirectory = mSeedsDirectory / std::to_string(dataModelPath.mClusterId);
    // Insert the command in the file at path "<seedsDirectory>/<clusterId>/<hashedValue>"
    if (!fs::exists(seedExportDirectory))
    {
        VerifyOrReturnError(!fs::create_directories(seedExportDirectory), CHIP_FUZZER_FILESYSTEM_ERROR);
    }

    auto fd = fopen((seedExportDirectory / fileName).c_str(), "w");
    VerifyOrReturnError(nullptr != fd, CHIP_FUZZER_FILESYSTEM_ERROR);

    fwrite(command, sizeof(char), strlen(command), fd);

    auto rv = fclose(fd);
    VerifyOrReturnError(EOF != rv, CHIP_FUZZER_FILESYSTEM_ERROR);

    ChipLogProgress(chipTool, "Logged well-formed command: %s", command);

    return CHIP_NO_ERROR;
}

std::function<const char *(fs::path)> fuzz::ConvertStringToGenerationFunction(const char * key)
{
    if (std::string(key).compare("seed-only") == 0)
    {
        return fuzz::generation::GenerateCommandSeedOnly;
    }
    else
    {
        return nullptr;
    }
}
