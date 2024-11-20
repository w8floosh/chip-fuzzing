#include "Oracle.h"
#include "Fuzzer.h"
#include "Utils.h"
namespace fuzz = chip::fuzzing;

const fuzz::OracleStatus & fuzz::Oracle::Consume(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject,
                                                 bool isCommand, const CHIP_ERROR & observed,
                                                 const chip::Optional<ClusterStatus> & observedClusterSpecific)
{
    mLastStatus = mCurrentStatus;
    if (observedClusterSpecific != chip::NullOptional)
    {
        // TODO: Implement cluster-specific status handling
        return mCurrentStatus;
    }
    if (observed == CHIP_ERROR_TIMEOUT)
    {
        if (mLastStatus == OracleStatus::TIMEOUT)
            // Device may have crashed
            mCurrentStatus = OracleStatus::UNREACHABLE;
        else
            mCurrentStatus = OracleStatus::TIMEOUT;
    }

    OracleResult result = mRuleMap.Query(endpoint, cluster, subject, isCommand, observed);
    mCurrentStatus      = result.statusResult;

    auto stateMonitor = Fuzzer::GetInstance()->GetStateMonitor();
    stateMonitor->TrackError(observed, result);

    return mCurrentStatus;
}

const fuzz::OracleRule fuzz::OracleRuleMap::kInvalidRule = OracleRule(kInvalidEndpointId, kInvalidClusterId, kInvalidCommandId);

const fuzz::OracleResult fuzz::OracleRuleMap::Query(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject,
                                                    bool isCommand, const CHIP_ERROR & observed)
{
    key_t key(endpoint, cluster, subject, isCommand);
    auto rule = mRuleMap.find(key);
    VerifyOrReturnValue(rule != mRuleMap.end(), OracleResult(kInvalidRule, observed));
    return OracleResult(rule->second, observed);
}

void fuzz::OracleRuleMap::Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId && cluster != kInvalidClusterId && command != kInvalidCommandId);
    key_t key(endpoint, cluster, command, true);
    VerifyOrDie(mRuleMap.emplace(key, OracleRule(endpoint, cluster, command)).second);
}
void fuzz::OracleRuleMap::Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command,
                              std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId && cluster != kInvalidClusterId && command != kInvalidCommandId);
    key_t key(endpoint, cluster, command, true);
    VerifyOrDie(mRuleMap.emplace(key, OracleRule(endpoint, cluster, command, expectedErrors)).second);
}

void fuzz::OracleRuleMap::Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command,
                              std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors, OracleRule::ExtraArgs extraArgs)
{
    VerifyOrReturn(endpoint != kInvalidEndpointId && cluster != kInvalidClusterId && command != kInvalidCommandId);
    key_t key(endpoint, cluster, command, true);
    VerifyOrDie(mRuleMap.emplace(key, OracleRule(endpoint, cluster, command, expectedErrors, extraArgs)).second);
}
