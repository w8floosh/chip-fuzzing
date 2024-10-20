#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"

using IMStatus = chip::Protocols::InteractionModel::Status;
namespace chip {
namespace fuzzing {

/**
 * @enum OracleStatus
 * @brief The OracleStatus enum represents the possible outcomes of the bug oracle's analysis.
 * The oracle status gives an insight into what went wrong with the device's behavior.
 */
enum class OracleStatus : uint8_t
// TODO: Create error description logs depending on the status
{
    OK,                  // Observed status matches the expected one
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
        std::optional<std::unordered_map<uint8_t, TLV::TLVType>> requiredCommandFields;
        std::optional<std::array<int64_t, 2>> constraintLimits;
    };

    OracleRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command) :
        mEndpointId(endpoint), mClusterId(cluster), mSubjectId(command), mIsCommand(true), mExtraArgs(std::nullopt)
    {
        mExpectedStatuses.push_back(IMStatus::Success);
        mExpectedStatuses.push_back(IMStatus::Failure);
        mExpectedStatuses.push_back(IMStatus::InvalidCommand);
        mExpectedStatuses.push_back(IMStatus::ConstraintError);
    };

    OracleRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command, ExtraArgs && extraArgs) :
        mEndpointId(endpoint), mClusterId(cluster), mSubjectId(command), mIsCommand(true), mExtraArgs(std::move(extraArgs))
    {
        mExpectedStatuses.push_back(IMStatus::InvalidCommand);
        mExpectedStatuses.push_back(IMStatus::ConstraintError);
        mExpectedStatuses.push_back(IMStatus::Success);
        mExpectedStatuses.push_back(IMStatus::Failure);
    };

    OracleRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
               std::vector<IMStatus> && expectedStatuses) :
        mEndpointId(endpoint), mClusterId(cluster), mSubjectId(attribute), mIsCommand(false), mExtraArgs(std::nullopt),
        mExpectedStatuses(std::move(expectedStatuses))
    {
        mExpectedStatuses.push_back(IMStatus::Success);
        mExpectedStatuses.push_back(IMStatus::Failure);
    };

    OracleRule & operator=(const OracleRule &) = default;

    /** Checks if the observed status matches at least one of the expected ones. */
    bool Query(const IMStatus & receivedStatus) const
    {
        VerifyOrReturnValue(mEndpointId != kInvalidEndpointId && mClusterId != kInvalidClusterId && mSubjectId != kInvalidCommandId,
                            false);
        for (const auto & status : mExpectedStatuses)
            if (status == receivedStatus)
                return true;
        return false;
    }

    /** TODO: Checks if the observed status matches at least one of the expected ones and the supplied payload respects all the
     * constraints. */
    // bool Query(const IMStatus & receivedStatus, Json::Value payload) const
    // {
    //     VerifyOrReturnValue(mEndpointId != kInvalidEndpointId && mClusterId != kInvalidClusterId && mSubjectId !=
    //     kInvalidCommandId,
    //                         false);
    //     if (mExtraArgs.has_value())
    //     {
    //         if (mExtraArgs->requiredCommandFields.has_value())
    //         {
    //             for (const auto & [fieldId, fieldType] : mExtraArgs->requiredCommandFields.value())
    //             {
    //                 if (payload[fieldId] != fieldType)
    //                     return false;
    //             }
    //         }
    //         if (mExtraArgs->constraintLimits.has_value())
    //         {
    //             auto [min, max] = mExtraArgs->constraintLimits.value();
    //             for (const auto & [fieldId, fieldType] : mExtraArgs->requiredCommandFields.value())
    //             {
    //                 if (payload[fieldId].type() != fieldType)
    //                     return false;
    //                 if (payload[fieldId].asInt64() < min || payload[fieldId].asInt64() > max)
    //                     return false;
    //             }
    //         }
    //     }
    //     return Query(receivedStatus);
    // }

private:
    const chip::EndpointId mEndpointId;
    const chip::ClusterId mClusterId;
    const uint32_t mSubjectId;
    const bool mIsCommand;
    const std::optional<ExtraArgs> mExtraArgs;
    std::vector<IMStatus> mExpectedStatuses;
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
    OracleResult(const OracleRule & rule, IMStatus observed) : usedRule(rule), queryResult(rule.Query(observed))
    {
        if (!queryResult)
            statusResult = OracleStatus::UNEXPECTED_RESPONSE;
    }
    OracleResult(const OracleRule & rule, bool result) : usedRule(rule), queryResult(result) {}
    OracleResult & operator=(OracleResult &) = default;
    const OracleRule & usedRule;
    bool queryResult;
    OracleStatus statusResult = OracleStatus::OK;
};

class OracleRuleMap
{
    using key_t = std::tuple<chip::EndpointId, chip::ClusterId, uint32_t, bool>;

public:
    const OracleResult Query(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject, bool isCommand,
                             const IMStatus & receivedStatus);
    void Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command);
    void Add(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
             std::vector<IMStatus> && expectedStatuses);

private:
    std::unordered_map<utils::OracleRuleMapKey, OracleRule, utils::MapKeyHasher, utils::MapKeyEqualizer> mRuleMap;

    static const OracleRule mInvalidRule;
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
    Oracle() = delete;
    Oracle(StateMonitor & sm) :
        mCurrentStatus(OracleStatus::INITIALIZED), mLastStatus(OracleStatus::UNINITIALIZED), mStateMonitor(sm) {};
    ~Oracle() {};

    const OracleStatus & Consume(chip::EndpointId endpoint, chip::ClusterId cluster, uint32_t subject, bool isCommand,
                                 const chip::app::StatusIB & observed,
                                 const chip::Optional<ClusterStatus> & observedClusterSpecific = chip::NullOptional);
    const OracleStatus & GetCurrentStatus() { return mCurrentStatus; };
    const OracleStatus & GetLastStatus() { return mLastStatus; };
    void AddRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::CommandId command)
    {
        mRuleMap.Add(endpoint, cluster, command);
    }
    void AddRule(chip::EndpointId endpoint, chip::ClusterId cluster, chip::AttributeId attribute,
                 std::vector<IMStatus> && expectedStatuses)
    {
        mRuleMap.Add(endpoint, cluster, attribute, std::move(expectedStatuses));
    }

private:
    OracleStatus mCurrentStatus;
    OracleStatus mLastStatus;
    OracleRuleMap mRuleMap;
    StateMonitor & mStateMonitor;
};
} // namespace fuzzing
}; // namespace chip
