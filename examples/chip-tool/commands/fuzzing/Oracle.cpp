#include "Oracle.h"
namespace fuzz = chip::fuzzing;

fuzz::OracleStatus & fuzz::Oracle::Consume(const chip::app::StatusIB & actual, chip::app::StatusIB & expected)
{
    return Consume(actual.ToChipError(), expected.ToChipError());
}

fuzz::OracleStatus & fuzz::Oracle::Consume(const CHIP_ERROR & actual, const CHIP_ERROR & expected)
{
    // TODO
    using State = OracleStatus;
    mLastStatus = mCurrentStatus;

    if (actual == expected)
    {
        mCurrentStatus = State::OK;
    }
    else
    {
        if (mLastStatus == State::OK)
        {
            mCurrentStatus = State::UNEXPECTED_RESPONSE;
        }
        else
        {
            mCurrentStatus = State::UNEXPECTED_BEHAVIOR;
        }
    }
    return mCurrentStatus;
} // namespace chip::fuzzing

template <class com_t, class attr_t>
bool fuzz::OracleRule<com_t, attr_t>::operator()(std::any value)
{
    // TODO
    return true;
}
