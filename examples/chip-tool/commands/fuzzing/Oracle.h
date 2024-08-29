#include <any>
namespace chip {
namespace fuzzing {

enum OracleStatus
// TODO: Create error description templates depending on the status
{
    OK,                    // Received status and value match the expected ones
    UNEXPECTED_TRANSITION, // Received value doesn't match with expected one
    UNEXPECTED_RESPONSE,   // Received status doesn't match with expected one
    UNEXPECTED_BEHAVIOR,   // Neither received value or status match expected ones
    DATA_MODEL_VIOLATION,  // Received information which violates the Matter standard
    UNRECOGNIZED_PATH,     // Received data which isn't on a standard path data
    OUT_OF_MEMORY,         // The device is out of memory
    BUSY,                  // The device is unresponsive or busy
};
class Oracle
{
public:
    Oracle() { mCurrentStatus = 0; };
    ~Oracle() {};

    // TODO: Edit signature to take AttributeDataIB/AttributeStatusIB as parameter too
    OracleStatus Consume(CHIP_ERROR actual, CHIP_ERROR expected);

private:
    int mCurrentStatus;
    int mLastStatus;
};
} // namespace fuzzing

// TODO: Find some standard way to represent specification rules (conformance?)
template <class CommandType, class AttrType>
struct OracleRule
{
    const AttrType desiredValue;
    const AttrType lastValue;
    std::any actualValue;
    bool operator()(std::any value); // checks if rule is fulfilled
};
}; // namespace chip
