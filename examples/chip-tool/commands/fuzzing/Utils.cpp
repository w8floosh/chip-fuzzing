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

std::string chip::fuzzing::GetElapsedTime(std::chrono::system_clock::time_point startTime)
{
    auto now     = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();

    int64_t hours   = elapsed / 3600;
    int64_t minutes = (elapsed % 3600) / 60;
    int64_t seconds = elapsed % 60;

    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << hours << ":" << std::setw(2) << std::setfill('0') << minutes << ":" << std::setw(2)
        << std::setfill('0') << seconds;

    return oss.str();
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
