#include "Oracle.h"
namespace fuzz = chip::fuzzing;

fuzz::OracleStatus & fuzz::Oracle::Consume(const chip::app::StatusIB & actual, chip::app::StatusIB & expected)
{
    return Consume(actual.ToChipError(), expected.ToChipError());
}

fuzz::OracleStatus & fuzz::Oracle::Consume(const CHIP_ERROR & actual, const CHIP_ERROR & expected)
{
    // TODO
    mLastStatus = mCurrentStatus;

    if (actual == expected)
    {
        mCurrentStatus = OracleStatus::OK;
    }
    else
    {
        if (mLastStatus == OracleStatus::OK)
        {
            mCurrentStatus = OracleStatus::UNEXPECTED_RESPONSE;
        }
        else
        {
            mCurrentStatus = OracleStatus::UNEXPECTED_BEHAVIOR;
        }
    }
    return mCurrentStatus;
} // namespace chip::fuzzing

fuzz::OracleResult fuzz::OracleRuleMap::Query(const chip::app::ConcreteDataAttributePath & path,
                                              const chip::Protocols::InteractionModel::Status & receivedStatus)
{
    return OracleResult(0, OracleRuleMap::kInvalidClusterOracleRule);
}

void fuzz::OracleRuleMap::Add(chip::app::ConcreteDataAttributePath path,
                              const chip::Protocols::InteractionModel::Status & expectedStatus)
{
    auto key = std::make_tuple(path.mClusterId, path.mAttributeId);
    mMap.emplace(key, OracleRule(path, expectedStatus));
    mNoRulesForCluster[std::get<0>(key)]++;
    mNoRulesForAttribute[std::get<1>(key)]++;
}
