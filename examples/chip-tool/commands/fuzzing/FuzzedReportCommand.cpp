// #include "FuzzedReportCommand.h"

// void FuzzedReportCommand::OnAttributeData(const chip::app::ConcreteDataAttributePath & path, chip::TLV::TLVReader * data,
//                                           const chip::app::StatusIB & status)
// {
//     CHIP_ERROR error = status.ToChipError();
//     if (CHIP_NO_ERROR != error)
//     {
//         LogErrorOnFailure(RemoteDataModelLogger::LogErrorAsJSON(path, status));

//         ChipLogError(chipTool, "Response Failure: %s", chip::ErrorStr(error));
//         mError = error;
//         return;
//     }

//     if (data == nullptr)
//     {
//         ChipLogError(chipTool, "Response Failure: No Data");
//         mError = CHIP_ERROR_INTERNAL;
//         return;
//     }

//     LogErrorOnFailure(RemoteDataModelLogger::LogAttributeAsJSON(path, data));

//     error = DataModelLogger::LogAttribute(path, data);
//     if (CHIP_NO_ERROR != error)
//     {
//         ChipLogError(chipTool, "Response Failure: Can not decode Data");
//         mError = error;
//         return;
//     }
// }

// void FuzzedReportCommand::OnEventData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
//                                       const chip::app::StatusIB * status)
// {
//     if (status != nullptr)
//     {
//         CHIP_ERROR error = status->ToChipError();
//         if (CHIP_NO_ERROR != error)
//         {
//             LogErrorOnFailure(RemoteDataModelLogger::LogErrorAsJSON(eventHeader, *status));

//             ChipLogError(chipTool, "Response Failure: %s", chip::ErrorStr(error));
//             mError = error;
//             return;
//         }
//     }

//     if (data == nullptr)
//     {
//         ChipLogError(chipTool, "Response Failure: No Data");
//         mError = CHIP_ERROR_INTERNAL;
//         return;
//     }

//     LogErrorOnFailure(RemoteDataModelLogger::LogEventAsJSON(eventHeader, data));

//     CHIP_ERROR error = DataModelLogger::LogEvent(eventHeader, data);
//     if (CHIP_NO_ERROR != error)
//     {
//         ChipLogError(chipTool, "Response Failure: Can not decode Data");
//         mError = error;
//         return;
//     }
// }

// void FuzzedReportCommand::OnError(CHIP_ERROR error)
// {
//     LogErrorOnFailure(RemoteDataModelLogger::LogErrorAsJSON(error));

//     ChipLogProgress(chipTool, "Error: %s", chip::ErrorStr(error));
//     mError = error;
// }
