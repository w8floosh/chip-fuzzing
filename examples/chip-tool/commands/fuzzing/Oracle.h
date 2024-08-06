#include <any>
namespace chip {
namespace fuzzing {
class Oracle
{
public:
    Oracle() { mCurrentStatus = 0; };
    ~Oracle() {};

    static int Consume(char * command, int * status);

private:
    int mCurrentStatus;
    int mLastStatus;
};
} // namespace fuzzing

template <class CommandType, class AttrType>
struct OracleRule
{
    const AttrType desiredValue;
    const AttrType lastValue;
    std::any actualValue;
    bool operator()(std::any value); // checks if rule is fulfilled
}
} // namespace chip
