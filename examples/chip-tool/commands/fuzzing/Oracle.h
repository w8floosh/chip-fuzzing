#pragma once

#include "DeviceStateManager.h"
#include <any>
namespace chip {
namespace fuzzing {

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
    INITIALIZED,   // Starting state: the oracle hasn't received any data yet
};
class Oracle
{
public:
    Oracle() : mCurrentStatus(OracleStatus::OK), mLastStatus(OracleStatus::INITIALIZED) {};
    ~Oracle() {};

    // TODO: Edit signature to take AttributeDataIB/AttributeStatusIB as parameter too
    OracleStatus & Consume(CHIP_ERROR actual, CHIP_ERROR expected);

private:
    OracleStatus mCurrentStatus;
    OracleStatus mLastStatus;
};

// TODO: Find some standard way to represent specification rules (conformance?)
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
