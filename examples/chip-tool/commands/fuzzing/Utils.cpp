#include "Utils.h"
#include "Oracle.h"
#include <iostream>
#include <sys/ioctl.h>

void chip::fuzzing::Indent(size_t indent)
{
    for (size_t i = 0; i < indent; i++)
    {
        std::cout << " ";
    }
}

std::string chip::fuzzing::GetElapsedTime(std::chrono::steady_clock::time_point startTime)
{
    auto now     = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();

    int64_t hours   = elapsed / 3600;
    int64_t minutes = (elapsed % 3600) / 60;
    int64_t seconds = elapsed % 60;

    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << hours << ":" << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << seconds;

    return oss.str();
}

void chip::fuzzing::PrintStatusLine(std::chrono::steady_clock::time_point startTime, std::atomic<uint32_t> & currentTest,
                                    uint32_t totalTests, CHIP_ERROR lastStatusResponse, const OracleStatus & oracleStatus)
{

    std::cout << "\033[1;1H\033[2K"; // Move to top row and clear the line

    // Set the background to orange and text to white
    std::cout << "\033[37;43m";

    // Print status line with the desired formatting
    std::cout << " Test: " << currentTest << "/" << totalTests << " | Last command response: " << std::hex
              << lastStatusResponse.AsInteger() << " | Oracle status: " << static_cast<uint8_t>(oracleStatus) << std::dec
              << " | Elapsed: " << GetElapsedTime(startTime) << "\u001b[0m" << std::flush;

    // Restore the cursor position
    std::cout << "\033[1B\033[0J" << std::flush;
}

bool chip::fuzzing::IsManufacturerSpecificTestingCluster(ClusterId cluster)
{
    /**
     * Standard clusters are in range 0x0000_0000 - 0x0007_FFFF.
     * Manufacturer-specific clusters are in range 0x0001_XXXX - 0xFFF4_YYYY, where XXXX >= FC00 and YYYY <= FFFE.
     * Valid mnufacturer-specific clusters IDs ranging from 0xFFF1_0000 to 0xFFF4_FFFE are reserved to testing.
     */
    uint32_t manufacturerCode        = cluster & 0xFFFF0000;
    uint32_t manufacturerProductCode = cluster & 0x0000FFFE;
    return manufacturerCode >= 0xFFF10000 && manufacturerCode <= 0xFFF4FFFE && manufacturerProductCode >= 0xFC00;
}
