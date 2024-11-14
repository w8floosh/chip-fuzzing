#include "Oracle.h"
#include "Fuzzing.h"
#include "Utils.h"
namespace fuzz = chip::fuzzing;

const fuzz::OracleStatus & fuzz::Oracle::Consume(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject,
                                                 bool isCommand, const chip::app::StatusIB & observed,
                                                 const chip::Optional<ClusterStatus> & observedClusterSpecific)
{
    mLastStatus = mCurrentStatus;
    if (observedClusterSpecific != chip::NullOptional)
    {
        // TODO: Implement cluster-specific status handling
        return mCurrentStatus;
    }
    if (observed.mStatus == IMStatus::Timeout)
    {
        if (mLastStatus == OracleStatus::TIMEOUT)
            // Device may have crashed
            mCurrentStatus = OracleStatus::UNREACHABLE;
        else
            mCurrentStatus = OracleStatus::TIMEOUT;
    }

    OracleResult result = mRuleMap.Query(endpoint, cluster, subject, isCommand, observed.mStatus);
    mCurrentStatus      = result.statusResult;

    mStateMonitor.TrackError(observed.ToChipError(), result);

    return mCurrentStatus;
}

const fuzz::OracleRule fuzz::OracleRuleMap::kInvalidRule = OracleRule(kInvalidEndpointId, kInvalidClusterId, kInvalidCommandId);

const fuzz::OracleResult fuzz::OracleRuleMap::Query(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject,
                                                    bool isCommand, const IMStatus & receivedStatus)
{
    key_t key(endpoint, cluster, subject, isCommand);
    auto rule = mRuleMap.find(key);
    VerifyOrReturnValue(rule != mRuleMap.end(), OracleResult(kInvalidRule, false));
    return OracleResult(rule->second, receivedStatus);
}

void fuzz::OracleRuleMap::Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId && cluster != kInvalidClusterId && command != kInvalidCommandId);
    key_t key(endpoint, cluster, command, true);
    VerifyOrDie(mRuleMap.emplace(key, OracleRule(endpoint, cluster, command)).second);
}
void fuzz::OracleRuleMap::Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command,
                              std::unordered_set<IMStatus> & expectedStatuses)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId && cluster != kInvalidClusterId && command != kInvalidCommandId);
    key_t key(endpoint, cluster, command, true);
    VerifyOrDie(mRuleMap.emplace(key, OracleRule(endpoint, cluster, command, expectedStatuses)).second);
}

void fuzz::OracleRuleMap::Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command,
                              std::unordered_set<IMStatus> & expectedStatuses, OracleRule::ExtraArgs extraArgs)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId && cluster != kInvalidClusterId && command != kInvalidCommandId);
    key_t key(endpoint, cluster, command, true);
    VerifyOrDie(mRuleMap.emplace(key, OracleRule(endpoint, cluster, command, expectedStatuses, extraArgs)).second);
}
