#include "Fuzzing.h"
#include <vector>

namespace fs = std::filesystem;
namespace chip {
namespace fuzzing {
namespace stateful {

class DeviceStateManager
{
public:
    DeviceStateManager()
    {
        VerifyOrDieWithMsg(CHIP_NO_ERROR == InitDeviceState(), chipFuzzer, "Could not initialize device state");
    };
    ~DeviceStateManager();

    template <class T>
    T * GetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, bool returnPreviousValue = false);

private:
    DeviceState mDeviceState;
    CHIP_ERROR InitDeviceState();
    template <class T>
    CHIP_ERROR SetAttribute(EndpointId endpoint, ClusterId cluster, AttributeId attribute, T value);
};

template <class T>
class AttributeState
{
public:
    T & operator()();
    AttributeState<T> & operator=(const T & aValue);

    AttributeId mAttributeId;

private:
    T * mValue;
};

struct ClusterState
{
    template <class T>
    AttributeState<T> * operator[](AttributeId id);
    ClusterId mClusterId;
    std::unordered_map<AttributeId, AttributeState<std::any> *> mAttributes;
};
struct EndpointState
{
    ClusterState * operator[](ClusterId id);
    EndpointId mEndpointId;
    std::unordered_map<ClusterId, ClusterState *> mClusters;
};

struct DeviceState
{
    EndpointState * operator[](EndpointId id);
    FabricId mFabric;
    VendorId mVendor;
    std::unordered_map<EndpointId, EndpointState *> mEndpoints;
};

class Fuzzer : public fuzzing::Fuzzer
{
public:
    Fuzzer(fs::path seedsDirectory, FuzzingStrategy strategy, chip::Optional<fs::path> stateLogExportDirectory) :
        fuzzing::Fuzzer(seedsDirectory, strategy), mLogExportDirectory(stateLogExportDirectory) {};
    ~Fuzzer();

private:
    std::unordered_map<chip::ClusterId, ClusterState> mFuzzedDeviceState;
    chip::Optional<fs::path> mLogExportDirectory;
};

class AFLPlusPlus : public Fuzzer
{
public:
    AFLPlusPlus(fs::path seedsDirectory, FuzzingStrategy strategy, chip::Optional<fs::path> stateLogExportDirectory) :
        Fuzzer(seedsDirectory, strategy, stateLogExportDirectory) {};
    ~AFLPlusPlus();

    char * GenerateCommand() override;
    CHIP_ERROR ProcessCommandExitStatus(const char * const & command, std::any output) override;
};

CHIP_ERROR Init(FuzzerType type, FuzzingStrategy strategy, fs::path seedsDirectory,
                chip::Optional<fs::path> stateLogExportDirectory, fuzzing::Fuzzer ** fuzzer);

} // namespace stateful
} // namespace fuzzing
} // namespace chip
