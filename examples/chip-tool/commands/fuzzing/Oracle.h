#pragma once
#include "ForwardDeclarations.h"
#include "Utils.h"

namespace chip {
namespace fuzzing {

/**
 * @enum OracleStatus
 * @brief The OracleStatus enum represents the possible outcomes of the bug oracle's analysis.
 * The oracle status gives an insight into what went wrong with the device's behavior.
 */
enum OracleStatus
// TODO: Create error description logs depending on the status
{
    OK,                    // Received status and value match the expected ones
    UNEXPECTED_TRANSITION, // Received value doesn't match with expected one
    UNEXPECTED_RESPONSE,   // Received status doesn't match with expected one
    UNEXPECTED_BEHAVIOR,   // Neither received value or status match expected ones
    DATA_MODEL_VIOLATION,  // Received information which violates the Matter standard
    // UNRECOGNIZED_PATH,     // Received data which isn't on a standard path
    OUT_OF_MEMORY, // The device is out of memory
    BUSY,          // The device is unresponsive or busy
    INITIALIZED,   // Initial current status: the oracle hasn't received any data yet
    UNINITIALIZED, // Initial last status: the oracle hasn't received any data yet
};

// TODO: Find some standard way to represent specification rules (conformance?)
/**
 * @class OracleRule
 * @brief The OracleRule struct represents a rule that the device's behavior must follow.
 * It should encode a representation of the conformance rules that the device must follow when in a certain state.
 */
class OracleRule
{
public:
    OracleRule(chip::app::ConcreteDataAttributePath dmPath, const chip::Protocols::InteractionModel::Status & expectedStatus) :
        mAttributePath(dmPath), mExpectedStatus(expectedStatus) {};

    OracleRule & operator=(const OracleRule &) = default;

    bool Query(const chip::Protocols::InteractionModel::Status & receivedStatus, const std::optional<AttributeState> & value) const
    {
        return receivedStatus == mExpectedStatus;
    }

private:
    const chip::app::ConcreteDataAttributePath mAttributePath;
    const chip::Protocols::InteractionModel::Status & mExpectedStatus;
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
 * - `status`: Represents the OracleStatus the oracle transitioned to.
 */
struct OracleResult
{
    OracleResult(int id, const OracleRule & rule) : invalidIdIndex(id), usedRule(rule) {}
    OracleResult & operator=(OracleResult &) = default;
    int invalidIdIndex;
    const OracleRule & usedRule;
    bool queryResult;
};

class OracleRuleMap
{
    using key_t = std::tuple<chip::ClusterId, chip::AttributeId>;

public:
    OracleResult Query(const chip::app::ConcreteDataAttributePath & path,
                       const chip::Protocols::InteractionModel::Status & receivedStatus);
    void Add(chip::app::ConcreteDataAttributePath path, const chip::Protocols::InteractionModel::Status & expectedStatus);

    static const OracleRule kInvalidClusterOracleRule;
    static const OracleRule kInvalidAttributeOracleRule;

private:
    struct PathHash
    {
        PathHash() : clusterHasher(), attributeHasher() {}
        std::hash<uint32_t> clusterHasher;
        std::hash<uint32_t> attributeHasher;
        std::size_t operator()(const key_t & k) const { return clusterHasher(std::get<0>(k)) ^ attributeHasher(std::get<1>(k)); }
    };

    struct PathEqual
    {
        bool operator()(const key_t & v0, const key_t & v1) const
        {
            return (std::get<0>(v0) == std::get<0>(v1) && std::get<1>(v0) == std::get<1>(v1));
        }
    };

    std::unordered_map<key_t, OracleRule, PathHash, PathEqual> mMap;
    std::unordered_map<chip::ClusterId, uint64_t> mNoRulesForCluster;
    std::unordered_map<chip::AttributeId, uint64_t> mNoRulesForAttribute;
};

const OracleRule kInvalidClusterOracleRule{ chip::app::ConcreteDataAttributePath(kInvalidEndpointId, kInvalidClusterId,
                                                                                 kInvalidAttributeId),
                                            chip::Protocols::InteractionModel::Status::UnsupportedCluster };
const OracleRule kInvalidAttributeOracleRule{ chip::app::ConcreteDataAttributePath(kInvalidEndpointId, kInvalidClusterId,
                                                                                   kInvalidAttributeId),
                                              chip::Protocols::InteractionModel::Status::UnsupportedAttribute };
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

    // TODO: Edit signature to take AttributeDataIB/AttributeStatusIB as parameter too
    OracleStatus & Consume(const CHIP_ERROR & actual, const CHIP_ERROR & expected);
    OracleStatus & Consume(const chip::app::StatusIB & actual, chip::app::StatusIB & expected);

private:
    OracleStatus mCurrentStatus;
    OracleStatus mLastStatus;
    OracleRuleMap mRuleMap;
};
} // namespace fuzzing
}; // namespace chip
