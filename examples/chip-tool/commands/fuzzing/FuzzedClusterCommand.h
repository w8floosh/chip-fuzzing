#include "../clusters/ClusterCommand.h"
#include "Fuzzing.h"
#include "Oracle.h"

class FuzzedClusterCommand : public ClusterCommand, public virtual InteractionModelCommands
{
public:
    FuzzedClusterCommand(CredentialIssuerCommands * credsIssuerConfig, CHIP_ERROR expectedError, chip::app::StatusIB expectedStatus,
                         chip::fuzzing::Fuzzer & fuzzer) :
        ClusterCommand(credsIssuerConfig), InteractionModelCommands(this), mExpectedError(expectedError),
        mExpectedStatus(expectedStatus), mFuzzer(fuzzer)
    {}

    FuzzedClusterCommand(chip::ClusterId clusterId, CredentialIssuerCommands * credsIssuerConfig, CHIP_ERROR expectedError,
                         chip::fuzzing::Fuzzer & fuzzer) :
        ClusterCommand(clusterId, credsIssuerConfig), InteractionModelCommands(this), mExpectedError(expectedError), mFuzzer(fuzzer)
    {}

    ~FuzzedClusterCommand() {}

    void OnResponse(chip::app::CommandSender * client, const chip::app::ConcreteCommandPath & path,
                    const chip::app::StatusIB & status, chip::TLV::TLVReader * data) override;
    void OnError(const chip::app::CommandSender * client, CHIP_ERROR error) override;

protected:
    FuzzedClusterCommand(char * commandName, CredentialIssuerCommands * credsIssuerConfig, CHIP_ERROR expectedError,
                         chip::app::StatusIB expectedStatus, chip::fuzzing::Fuzzer & fuzzer) :
        ClusterCommand(credsIssuerConfig), InteractionModelCommands(this), mExpectedStatus(expectedStatus),
        mExpectedError(expectedError), mFuzzer(fuzzer)
    {
        // Subclasses are responsible for calling AddArguments.
    }
    // TODO: Add protected constructor called when command is specified by name as in ClusterCommand
private:
    CHIP_ERROR mExpectedError = CHIP_NO_ERROR;
    chip::app::StatusIB mExpectedStatus;
    chip::fuzzing::Fuzzer & mFuzzer;
};
