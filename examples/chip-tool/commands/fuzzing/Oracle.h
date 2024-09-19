#pragma once
#include "ForwardDeclarations.h"
#include <any>

namespace chip {
namespace fuzzing {

/**
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
};

// TODO: Find some standard way to represent specification rules (conformance?)
/**
 * @brief The OracleRule struct represents a rule that the device's behavior must follow.
 * It should encode a representation of the conformance rules that the device must follow when in a certain state.
 */
template <class com_t, class attr_t>
struct OracleRule
{
    const attr_t desiredValue;
    const attr_t lastValue;
    std::any actualValue;
    bool operator()(std::any value); // checks if rule is fulfilled
};

} // namespace fuzzing
}; // namespace chip
