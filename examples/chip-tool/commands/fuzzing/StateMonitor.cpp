#include "StateMonitor.h"
#include "Fuzzer.h"
#include "Oracle.h"
#include "Utils.h"
#include <fstream>
#include <yaml-cpp/yaml.h>

void fuzz::StateMonitor::DumpTelemetry()
{
    YAML::Emitter os;
    std::unordered_map<chip::app::ConcreteCommandPath, std::unordered_map<CHIP_ERROR, uint64_t, utils::MapKeyHasher>,
                       utils::MapKeyHasher>
        mErrorCountersPerCommand;

    std::time_t time  = std::chrono::system_clock::to_time_t(mStartTime);
    std::tm * utcTime = std::gmtime(&time);
    std::ostringstream oss;
    oss << std::put_time(utcTime, "%Y-%m-%d %H:%M:%S UTC");

    os << YAML::BeginMap;
    os << YAML::Key << "started" << YAML::Value << oss.str();
    os << YAML::Key << "elapsed" << YAML::Value << fuzz::GetElapsedTime(mStartTime);
    os << YAML::Key << "explorationStats" << YAML::Value << YAML::BeginMap;

    os << YAML::Key << "skipped" << YAML::Value << mSkippedExplorationTests;
    os << YAML::Key << "errors" << YAML::Value << YAML::BeginSeq;
    for (auto & [err, totalCount] : mExplorationErrorCounters)
    {
        os << YAML::BeginMap;
        os << YAML::Key << "code" << YAML::Value << YAML::Hex << err.AsInteger() << YAML::Dec;
        os << YAML::Key << "total" << YAML::Value << totalCount;
        os << YAML::EndMap;
    }
    os << YAML::EndSeq << YAML::EndMap;

    os << YAML::Key << "testStats" << YAML::Value << YAML::BeginMap;
    os << YAML::Key << "skipped" << YAML::Value << mSkippedTests;
    os << YAML::Key << "errors" << YAML::Value << YAML::BeginSeq;

    for (auto & [err, totalCount] : mTestingErrorCounters)
    {
        os << YAML::BeginMap;
        os << YAML::Key << "code" << YAML::Value << YAML::Hex << err.AsInteger() << YAML::Dec;
        os << YAML::Key << "total" << YAML::Value << totalCount;
        os << YAML::Key << "expected" << YAML::Value << mExpectedErrorCounters[err];
        os << YAML::Key << "unexpected" << YAML::Value << mUnexpectedErrorCounters[err];
        os << YAML::EndMap;
    }
    os << YAML::EndSeq << YAML::EndMap;

    os << YAML::Key << "observationStats" << YAML::Value << YAML::BeginSeq;
    for (auto & [obs, count] : mObservationCounters)
    {
        mErrorCountersPerCommand[obs.mCommandPath][obs.mStatusResponse] += count;

        os << YAML::BeginMap;

        os << YAML::Key << "path" << YAML::Value << YAML::BeginMap;
        os << YAML::Key << "endpoint" << YAML::Value << YAML::Hex << obs.mCommandPath.mEndpointId;
        os << YAML::Key << "cluster" << YAML::Value << YAML::Hex << obs.mCommandPath.mClusterId;
        os << YAML::Key << "command" << YAML::Value << YAML::Hex << obs.mCommandPath.mCommandId << YAML::EndMap;

        os << YAML::Key << "statusResponse" << YAML::Value << YAML::Hex << obs.mStatusResponse.AsInteger();
        os << YAML::Key << "changedAttributes" << YAML::Value << YAML::BeginSeq;
        for (auto & path : obs.mChangedAttributes)
        {
            os << YAML::BeginMap;
            os << YAML::Key << "endpoint" << YAML::Value << path.mEndpointId;
            os << YAML::Key << "cluster" << YAML::Value << path.mClusterId;
            os << YAML::Key << "attribute" << YAML::Value << path.mAttributeId;
            os << YAML::EndMap;
        }
        os << YAML::EndSeq;

        os << YAML::Key << "times" << YAML::Value << count << YAML::EndMap;
    }
    os << YAML::EndSeq;

    os << YAML::Key << "errorStatsPerCommand" << YAML::Value << YAML::BeginSeq;
    for (auto & [comPath, errors] : mErrorCountersPerCommand)
    {
        os << YAML::BeginMap;
        os << YAML::Key << "path" << YAML::Value << YAML::BeginMap;
        os << YAML::Key << "endpoint" << YAML::Value << YAML::Hex << comPath.mEndpointId;
        os << YAML::Key << "cluster" << YAML::Value << YAML::Hex << comPath.mClusterId;
        os << YAML::Key << "command" << YAML::Value << YAML::Hex << comPath.mCommandId << YAML::EndMap;
        os << YAML::Key << "errors" << YAML::Value << YAML::BeginSeq;
        for (auto & [err, count] : errors)
        {
            os << YAML::BeginMap;
            os << YAML::Key << "code" << YAML::Value << YAML::Hex << err.AsInteger() << YAML::Dec;
            os << YAML::Key << "total" << YAML::Value << count;
            os << YAML::EndMap;
        }
        os << YAML::EndSeq << YAML::EndMap;
    }
    os << YAML::EndSeq;

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(mStartTime.time_since_epoch()).count();
    std::string fileName(std::to_string(now_ms));
    std::ofstream file(mDumpDirectory / (fileName + "_telemetry.yaml"));
    file << os.c_str();
    file.close();
}

void fuzz::StateMonitor::TrackError(const CHIP_ERROR & err)
{
    if (Fuzzer::GetInstance()->CurrentPhase() == FuzzerPhase::TESTING)
        mTestingErrorCounters[err]++;
    else
        mExplorationErrorCounters[err]++;
}

void fuzz::StateMonitor::TrackError(const CHIP_ERROR & err, OracleResult & ores)
{
    VerifyOrReturn(Fuzzer::GetInstance()->CurrentPhase() == FuzzerPhase::TESTING);
    mTestingErrorCounters[err]++;
    ores.queryResult ? mExpectedErrorCounters[err]++ : mUnexpectedErrorCounters[err]++;
}

void fuzz::StateMonitor::TrackSkipped()
{
    if (Fuzzer::GetInstance()->CurrentPhase() == FuzzerPhase::TESTING)
        mSkippedTests++;
    else
        mSkippedExplorationTests++;
}
void fuzz::StateMonitor::LogObservation(const utils::FuzzerObservation & observation)
{
    mObservationCounters[observation]++;
}

void fuzz::StateMonitor::DumpObservation(const utils::FuzzerObservation & observation)
{
    YAML::Emitter os;

    os << YAML::BeginMap;
    os << YAML::Key << "endpoint" << YAML::Value << observation.mCommandPath.mEndpointId;
    os << YAML::Key << "cluster" << YAML::Value << observation.mCommandPath.mClusterId;
    os << YAML::Key << "command" << YAML::Value << observation.mCommandPath.mCommandId;
    os << YAML::Key << "statusResponse" << YAML::Value << YAML::Hex << observation.mStatusResponse.AsInteger();
    os << YAML::Key << "changedAttributes" << YAML::Value << YAML::BeginSeq;
    for (auto & path : observation.mChangedAttributes)
    {
        os << YAML::BeginMap;
        os << YAML::Key << "endpoint" << YAML::Value << YAML::Hex << path.mEndpointId;
        os << YAML::Key << "cluster" << YAML::Value << YAML::Hex << path.mClusterId;
        os << YAML::Key << "attribute" << YAML::Value << YAML::Hex << path.mAttributeId;
        os << YAML::EndMap;
    }
    os << YAML::EndSeq;
    os << YAML::EndMap;
    auto now    = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::string fileName(std::to_string(now_ms));
    std::ofstream file(mDumpDirectory / fileName);
    file << os.c_str();
    file.close();
}
