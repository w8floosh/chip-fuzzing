#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"
#include <app/MessageDef/StatusIB.h>
#include <json/json.h>

namespace chip {
namespace fuzzing {

/**
 * @enum OracleStatus
 * @brief The OracleStatus enum represents the possible outcomes of the bug oracle's analysis.
 * The oracle status gives an insight into what went wrong with the device's behavior.
 */
// TODO: Create error description logs depending on the status
enum class OracleStatus : uint8_t
{
    SUCCESS,             // Observed status matches the expected one
    UNEXPECTED_RESPONSE, // Observed status doesn't match with expected one
    TIMEOUT,       // The device is either unresponsive or busy. Oracle transitions to this state when the device timeouts once
    UNREACHABLE,   // The device likely may have crashed. Oracle transitions to this state when the device timeouts while the oracle
                   // status is TIMEOUT
    INITIALIZED,   // Initial current status: the oracle hasn't received any data yet
    UNINITIALIZED, // Initial last status: the oracle hasn't received any data yet
};

/**
 * @class OracleRule
 * @brief The OracleRule struct represents a rule that the device's behavior must follow.
 * It should encode a representation of the conformance rules that the device must follow when in a certain state.
 */
class OracleRule
{
public:
    struct ExtraArgs
    {
        std::map<uint8_t, const std::pair<chip::TLV::TLVType, uint8_t>> * requiredCommandFields = nullptr;
        std::array<int64_t, 2> * constraintLimits                                               = nullptr;
    };

    OracleRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command) :
        mEndpointId(endpoint), mClusterId(cluster), mSubjectId(command), mIsCommand(true), mExtraArgs(chip::NullOptional),
        mExpectedErrors({ CHIP_NO_ERROR }) {};

    OracleRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
               std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors) :
        mEndpointId(endpoint), mClusterId(cluster), mSubjectId(attribute), mIsCommand(false), mExtraArgs(chip::NullOptional),
        mExpectedErrors(expectedErrors) {};

    OracleRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
               std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors, ExtraArgs extraArgs) :
        mEndpointId(endpoint), mClusterId(cluster), mSubjectId(attribute), mIsCommand(false), mExtraArgs(extraArgs),
        mExpectedErrors(expectedErrors) {};

    OracleRule & operator=(const OracleRule &) = default;

    /** Checks if the observed status matches at least one of the expected ones. */
    bool Query(const CHIP_ERROR & observed) const
    {
        VerifyOrReturnValue(mEndpointId != kInvalidEndpointId && mClusterId != kInvalidClusterId && mSubjectId != kInvalidCommandId,
                            false);
        for (const auto & error : mExpectedErrors)
        {
            if (error == observed)
                return true;
        }
        return false;
    }

    /** TODO: Checks if the observed status matches at least one of the expected ones and the supplied payload respects all the
     * constraints. */
    bool Query(const CHIP_ERROR & observed, Json::Value & payload) const { return false; }

private:
    const chip::EndpointId mEndpointId;
    const chip::ClusterId mClusterId;
    const uint32_t mSubjectId;
    const bool mIsCommand;
    const chip::Optional<ExtraArgs> mExtraArgs;
    std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> mExpectedErrors;
};

/**
 * @struct OracleResult
 * @brief Encodes the result of a consume operation of the oracle.
 *
 * This struct contains information about the consume's outcome:
 *
 * - `invalidIdIndex`: is the index of the first invalid element of the map key tuple (`std::tuple<chip::NodeId, chip::EndpointId,
 * chip::ClusterId, chip::AttributeId>`) if no valid rule to query was found for that path or -1 if the path is valid.
 *
 * - `usedRule` is a pointer to the queried rule.
 *
 * - `queryResult`: indicates if the rule was fulfilled or not (i.e. the query result).
 *
 * - `statusResult`: Represents the OracleStatus the oracle should transition to.
 */
struct OracleResult
{
    OracleResult(const OracleRule & rule, const CHIP_ERROR & observed) : usedRule(rule), queryResult(rule.Query(observed))
    {
        if (!queryResult)
            statusResult = OracleStatus::UNEXPECTED_RESPONSE;
    }
    OracleResult & operator=(OracleResult &) = default;
    const OracleRule & usedRule;
    bool queryResult;
    OracleStatus statusResult = OracleStatus::SUCCESS;
};

class OracleRuleMap
{
    using key_t = std::tuple<chip::EndpointId, chip::ClusterId, uint32_t, bool>;

public:
    const OracleResult Query(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject, bool isCommand,
                             const CHIP_ERROR & observed);
    void Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command);
    void Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
             std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors);
    void Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
             std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors, OracleRule::ExtraArgs extraArgs);

private:
    std::unordered_map<utils::OracleRuleMapKey, OracleRule, utils::MapKeyHasher, utils::MapKeyEqualizer> mRuleMap;
    static const OracleRule kInvalidRule;
};

/**
 * @class Oracle
 * @brief The bug oracle checks if the received response status/error was expected or not.
 * If not, it dumps the device's current state and the received data to a file, also logging the error.
 * In other words, it checks if the device is behaving as expected.
 */

class Oracle
{
public:
    Oracle() : mCurrentStatus(OracleStatus::INITIALIZED), mLastStatus(OracleStatus::UNINITIALIZED) {};
    ~Oracle() {};

    const OracleStatus & Consume(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject, bool isCommand,
                                 const CHIP_ERROR & observed,
                                 const chip::Optional<ClusterStatus> & observedClusterSpecific = chip::NullOptional);
    const OracleStatus & GetCurrentStatus() { return mCurrentStatus; };
    const OracleStatus & GetLastStatus() { return mLastStatus; };
    void AddRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command)
    {
        mRuleMap.Add(endpoint, cluster, command);
    }
    void AddRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
                 std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors)
    {
        mRuleMap.Add(endpoint, cluster, attribute, expectedErrors);
    }
    void AddRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
                 std::unordered_set<CHIP_ERROR, utils::SetKeyHasher> & expectedErrors, OracleRule::ExtraArgs extraArgs)
    {
        mRuleMap.Add(endpoint, cluster, attribute, expectedErrors, extraArgs);
    }

private:
    OracleStatus mCurrentStatus;
    OracleStatus mLastStatus;
    OracleRuleMap mRuleMap;
};
} // namespace fuzzing
}; // namespace chip
