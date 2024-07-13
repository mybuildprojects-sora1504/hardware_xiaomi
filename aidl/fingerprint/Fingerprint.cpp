/*
 * Copyright (C) 2020 The Android Open Source Project
 *               2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Fingerprint.h"
#include "LegacyFingerprint.h"
#include "Session.h"

#include <android-base/properties.h>
#include <fingerprint.sysprop.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

namespace {

typedef struct fingerprint_hal {
    const char* class_name;
    const bool is_udfps;
} fingerprint_hal_t;

static const fingerprint_hal_t kModules[] = {
        {"fpc", false},        {"fpc_fod", true}, {"goodix", false}, {"goodix_fod", true},
        {"goodix_fod6", true}, {"silead", false}, {"syna", true},
};

}  // anonymous namespace

using namespace ::android::fingerprint::virt;

namespace aidl::android::hardware::biometrics::fingerprint {
namespace {
constexpr size_t MAX_WORKER_QUEUE_SIZE = 5;
constexpr int SENSOR_ID = 5;
constexpr common::SensorStrength SENSOR_STRENGTH = common::SensorStrength::STRONG;
constexpr int MAX_ENROLLMENTS_PER_USER = 5;
constexpr bool SUPPORTS_NAVIGATION_GESTURES = true;
constexpr char HW_COMPONENT_ID[] = "fingerprintSensor";
constexpr char HW_VERSION[] = "vendor/model/revision";
constexpr char FW_VERSION[] = "1.01";
constexpr char SERIAL_NUMBER[] = "00000001";
constexpr char SW_COMPONENT_ID[] = "matchingAlgorithm";
constexpr char SW_VERSION[] = "vendor/version/revision";

}  // namespace

Fingerprint::Fingerprint() : mWorker(MAX_WORKER_QUEUE_SIZE), mDevice(nullptr), mIsUdfps(false) {
    std::string sensorTypeProp = Fingerprint::cfg().get<std::string>("type");
    if (sensorTypeProp == "" || sensorTypeProp == "default" || sensorTypeProp == "rear") {
        mSensorType = FingerprintSensorType::REAR;
        mEngine = std::make_unique<FakeFingerprintEngineRear>();
    } else if (sensorTypeProp == "udfps") {
        mSensorType = FingerprintSensorType::UNDER_DISPLAY_OPTICAL;
        mEngine = std::make_unique<FakeFingerprintEngineUdfps>();
    } else if (sensorTypeProp == "side") {
        mSensorType = FingerprintSensorType::POWER_BUTTON;
        mEngine = std::make_unique<FakeFingerprintEngineSide>();
    } else {
        mSensorType = FingerprintSensorType::UNKNOWN;
        mEngine = std::make_unique<FakeFingerprintEngineRear>();
        UNIMPLEMENTED(FATAL) << "unrecognized or unimplemented fingerprint behavior: "
                             << sensorTypeProp;
    }
    LOG(INFO) << "sensorTypeProp:" << sensorTypeProp;
    LOG(INFO) << "ro.product.name=" << ::android::base::GetProperty("ro.product.name", "UNKNOWN");

    for (auto& [class_name, is_udfps] : kModules) {
        mDevice = openHal(class_name.c_str());
        if (!mDevice) {
            ALOGE("Can't open HAL module, class %s", class_name.c_str());
            continue;
        }

        ALOGI("Opened fingerprint HAL, class %s", class_name.c_str());
        mIsUdfps = is_udfps;
        break;
    }

    if (!mDevice) {
        ALOGE("Can't open any HAL module");
    }
}

fingerprint_device_t* Fingerprint::openHal(const char* class_name) {
    const hw_module_t* hw_mdl = nullptr;

    ALOGD("Opening fingerprint hal library...");
    if (hw_get_module_by_class(FINGERPRINT_HARDWARE_MODULE_ID, class_name, &hw_mdl) != 0) {
        ALOGE("Can't open fingerprint HW Module");
        return nullptr;
    }

    if (!hw_mdl) {
        ALOGE("No valid fingerprint module");
        return nullptr;
    }

    auto module = reinterpret_cast<const fingerprint_module_t*>(hw_mdl);
    if (!module->common.methods->open) {
        ALOGE("No valid open method");
        return nullptr;
    }

    hw_device_t* device = nullptr;
    if (module->common.methods->open(hw_mdl, nullptr, &device) != 0) {
        ALOGE("Can't open fingerprint methods");
        return nullptr;
    }

    auto fp_device = reinterpret_cast<fingerprint_device_t*>(device);
    if (fp_device->set_notify(fp_device, Fingerprint::notify) != 0) {
        ALOGE("Can't register fingerprint module callback");
        return nullptr;
    }

    return fp_device;
}

Return<bool> Fingerprint::isUdfps(uint32_t /*sensorId*/) {
    return mIsUdfps;
}

ndk::ScopedAStatus Fingerprint::getSensorProps(std::vector<SensorProps>* out) {
    std::vector<common::ComponentInfo> componentInfo = {
            {HW_COMPONENT_ID, HW_VERSION, FW_VERSION, SERIAL_NUMBER, "" /* softwareVersion */},
            {SW_COMPONENT_ID, "" /* hardwareVersion */, "" /* firmwareVersion */,
             "" /* serialNumber */, SW_VERSION}};
    auto sensorId = Fingerprint::cfg().get<std::int32_t>("sensor_id");
    auto sensorStrength = Fingerprint::cfg().get<std::int32_t>("sensor_strength");
    auto maxEnrollments = Fingerprint::cfg().get<std::int32_t>("max_enrollments");
    auto navigationGuesture = Fingerprint::cfg().get<bool>("navigation_guesture");
    auto detectInteraction = Fingerprint::cfg().get<bool>("detect_interaction");
    auto displayTouch = Fingerprint::cfg().get<bool>("display_touch");
    auto controlIllumination = Fingerprint::cfg().get<bool>("control_illumination");

    common::CommonProps commonProps = {sensorId, (common::SensorStrength)sensorStrength,
                                       maxEnrollments, componentInfo};

    SensorLocation sensorLocation = mEngine->getSensorLocation();

    LOG(INFO) << "sensor type:" << ::android::internal::ToString(mSensorType)
              << " location:" << sensorLocation.toString();

    *out = {{commonProps,
             mSensorType,
             {sensorLocation},
             navigationGuesture,
             detectInteraction,
             displayTouch,
             controlIllumination,
             std::nullopt}};
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Fingerprint::createSession(int32_t sensorId, int32_t userId,
                                              const std::shared_ptr<ISessionCallback>& cb,
                                              std::shared_ptr<ISession>* out) {
    CHECK(mSession == nullptr || mSession->isClosed()) << "Open session already exists!";

    mSession = SharedRefBase::make<Session>(sensorId, userId, cb, mEngine.get(), &mWorker);
    *out = mSession;

    mSession->linkToDeath(cb->asBinder().get());

    LOG(INFO) << __func__ << ": sensorId:" << sensorId << " userId:" << userId;
    return ndk::ScopedAStatus::ok();
}

binder_status_t Fingerprint::dump(int fd, const char** /*args*/, uint32_t numArgs) {
    if (fd < 0) {
        LOG(ERROR) << __func__ << "fd invalid: " << fd;
        return STATUS_BAD_VALUE;
    } else {
        LOG(INFO) << __func__ << " fd:" << fd << "numArgs:" << numArgs;
    }

    dprintf(fd, "----- FingerprintVirtualHal::dump -----\n");
    std::vector<SensorProps> sps(1);
    getSensorProps(&sps);
    for (auto& sp : sps) {
        ::android::base::WriteStringToFd(sp.toString(), fd);
    }
    ::android::base::WriteStringToFd(mEngine->toString(), fd);

    fsync(fd);
    return STATUS_OK;
}

binder_status_t Fingerprint::handleShellCommand(int in, int out, int err, const char** args,
                                                uint32_t numArgs) {
    LOG(INFO) << __func__ << " in:" << in << " out:" << out << " err:" << err
              << " numArgs:" << numArgs;

    if (numArgs == 0) {
        LOG(INFO) << __func__ << ": available commands";
        onHelp(out);
        return STATUS_OK;
    }

    for (auto&& str : std::vector<std::string_view>(args, args + numArgs)) {
        std::string option = str.data();
        if (option.find("clearconfig") != std::string::npos ||
            option.find("resetconfig") != std::string::npos) {
            resetConfigToDefault();
        }
        if (option.find("help") != std::string::npos) {
            onHelp(out);
        }
    }

    return STATUS_OK;
}

void Fingerprint::onHelp(int fd) {
    dprintf(fd, "Virtual HAL commands:\n");
    dprintf(fd, "         help: print this help\n");
    dprintf(fd, "  resetconfig: reset all configuration to default\n");
    dprintf(fd, "\n");
    fsync(fd);
}

void Fingerprint::resetConfigToDefault() {
    LOG(INFO) << __func__ << ": reset virtual HAL configuration to default";
    Fingerprint::cfg().init();
#ifdef FPS_DEBUGGABLE
    clearConfigSysprop();
#endif
}

void Fingerprint::clearConfigSysprop() {
    LOG(INFO) << __func__ << ": clear all systprop configuration";
#define RESET_CONFIG_O(__NAME__) \
    if (FingerprintHalProperties::__NAME__()) FingerprintHalProperties::__NAME__(std::nullopt)
#define RESET_CONFIG_V(__NAME__)                       \
    if (!FingerprintHalProperties::__NAME__().empty()) \
    FingerprintHalProperties::__NAME__({std::nullopt})

    RESET_CONFIG_O(type);
    RESET_CONFIG_V(enrollments);
    RESET_CONFIG_O(enrollment_hit);
    RESET_CONFIG_O(authenticator_id);
    RESET_CONFIG_O(challenge);
    RESET_CONFIG_O(lockout);
    RESET_CONFIG_O(operation_authenticate_fails);
    RESET_CONFIG_O(operation_detect_interaction_error);
    RESET_CONFIG_O(operation_enroll_error);
    RESET_CONFIG_V(operation_authenticate_latency);
    RESET_CONFIG_V(operation_detect_interaction_latency);
    RESET_CONFIG_V(operation_enroll_latency);
    RESET_CONFIG_O(operation_authenticate_duration);
    RESET_CONFIG_O(operation_authenticate_error);
    RESET_CONFIG_O(sensor_location);
    RESET_CONFIG_O(operation_authenticate_acquired);
    RESET_CONFIG_O(operation_detect_interaction_duration);
    RESET_CONFIG_O(operation_detect_interaction_acquired);
    RESET_CONFIG_O(sensor_id);
    RESET_CONFIG_O(sensor_strength);
    RESET_CONFIG_O(max_enrollments);
    RESET_CONFIG_O(navigation_guesture);
    RESET_CONFIG_O(detect_interaction);
    RESET_CONFIG_O(display_touch);
    RESET_CONFIG_O(control_illumination);
    RESET_CONFIG_O(lockout_enable);
    RESET_CONFIG_O(lockout_timed_threshold);
    RESET_CONFIG_O(lockout_timed_duration);
    RESET_CONFIG_O(lockout_permanent_threshold);
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
