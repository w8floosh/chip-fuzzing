// #include "../clusters/ReportCommand.h"
// class FuzzedReportCommand : public ReportCommand
// {
//     FuzzedReportCommand(const char * commandName, CredentialIssuerCommands * credsIssuerConfig) :
//         ReportCommand(commandName, credsIssuerConfig) {};

//     /////////// ReadClient Callback Interface /////////
//     void OnAttributeData(const chip::app::ConcreteDataAttributePath & path, chip::TLV::TLVReader * data,
//                          const chip::app::StatusIB & status);
//     void OnEventData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data, const chip::app::StatusIB *
//     status); void OnError(CHIP_ERROR error);
// };
