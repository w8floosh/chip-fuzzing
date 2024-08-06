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
} // namespace chip
