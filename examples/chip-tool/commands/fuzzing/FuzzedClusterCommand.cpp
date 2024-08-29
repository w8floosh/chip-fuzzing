#include "FuzzedClusterCommand.h"
void FuzzedClusterCommand::OnResponse(chip::app::CommandSender * client, const chip::app::ConcreteCommandPath & path,
                                      const chip::app::StatusIB & status, chip::TLV::TLVReader * data)
{

    ClusterCommand::OnResponse(client, path, status, data);
    mFuzzer.ProcessCommandOutput(data, path, status.ToChipError(), mExpectedError, status, mExpectedStatus);
}

void FuzzedClusterCommand::OnError(const chip::app::CommandSender * client, CHIP_ERROR error)
{
    ClusterCommand::OnError(client, error);
    mFuzzer.ProcessCommandOutput(error, mExpectedError);
}
