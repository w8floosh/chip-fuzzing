#pragma once
#include "ForwardDeclarations.h"
#include <app/EventHeader.h>
#include <app/MessageDef/StatusIB.h>
namespace chip {
namespace fuzzing {
class CallbackInterceptor
{
public:
    CallbackInterceptor() {}
    // Analyzes data coming from the ClusterCommand::OnResponse callback.
    void AnalyzeCommandResponse(chip::TLV::TLVReader * data, const chip::app::ConcreteCommandPath & path,
                                const chip::app::StatusIB & status);

    // Analyzes data coming from the ReportCommand::OnAttributeData and WriteAttributeCommand::OnResponse callbacks.
    void ProcessReportData(chip::TLV::TLVReader * data, const chip::app::ConcreteDataAttributePath & path,
                           const chip::app::StatusIB & status);

    // Analyzes data coming from the ReportCommand::OnEventData callback.
    void ProcessReportData(const chip::app::EventHeader & eventHeader, chip::TLV::TLVReader * data,
                           const chip::app::StatusIB * status);

    /**
     * Analyzes a recoverable error occurred while reporting, i.e. errors on single attributes in a transaction that involves
     * multiple ones. Currently it is only used when a read operation on an attribute with manufacturer-specific default value
     * conformance is done. In such case, the attribute value is uninitialized and it needs to be written at least once before
     * attempting a successful read.
     */
    void AnalyzeReportError(const chip::app::ConcreteDataAttributePath & path, const chip::app::StatusIB & status);

    // Analyzes data coming from the OnError callbacks.
    void AnalyzeCommandError(const chip::Protocols::InteractionModel::MsgType messageType, CHIP_ERROR error,
                             CHIP_ERROR expectedError = CHIP_NO_ERROR);
};

} // namespace fuzzing
} // namespace chip
