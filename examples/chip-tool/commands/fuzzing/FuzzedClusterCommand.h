#pragma once

#include "../clusters/ClusterCommand.h"
#include "Fuzzing.h"
#include "Oracle.h"

class FuzzedClusterCommand : public ClusterCommand
{
public:
    FuzzedClusterCommand(CredentialIssuerCommands * credsIssuerConfig, CHIP_ERROR expectedError, chip::app::StatusIB expectedStatus,
                         chip::fuzzing::Fuzzer & fuzzer) :
        ClusterCommand(credsIssuerConfig), mExpectedError(expectedError), mExpectedStatus(expectedStatus), mFuzzer(fuzzer)
    {
        mCallback = this;
        ResetOptions();
    }

    FuzzedClusterCommand(chip::ClusterId clusterId, CredentialIssuerCommands * credsIssuerConfig, CHIP_ERROR expectedError,
                         chip::app::StatusIB expectedStatus, chip::fuzzing::Fuzzer & fuzzer) :
        ClusterCommand(clusterId, credsIssuerConfig), mExpectedError(expectedError), mExpectedStatus(expectedStatus),
        mFuzzer(fuzzer)
    {
        mCallback = this;
        ResetOptions();
    }

    ~FuzzedClusterCommand() {}

    void OnResponse(chip::app::CommandSender * client, const chip::app::ConcreteCommandPath & path,
                    const chip::app::StatusIB & status, chip::TLV::TLVReader * data) override;
    void OnError(const chip::app::CommandSender * client, CHIP_ERROR error) override;

protected:
    FuzzedClusterCommand(char * commandName, CredentialIssuerCommands * credsIssuerConfig, CHIP_ERROR expectedError,
                         chip::app::StatusIB expectedStatus, chip::fuzzing::Fuzzer & fuzzer) :
        ClusterCommand(credsIssuerConfig), mExpectedError(expectedError), mExpectedStatus(expectedStatus), mFuzzer(fuzzer)
    {
        mCallback = this;
        ResetOptions();
    }

private:
    CHIP_ERROR mExpectedError;
    chip::app::StatusIB mExpectedStatus;
    chip::fuzzing::Fuzzer & mFuzzer;
};
