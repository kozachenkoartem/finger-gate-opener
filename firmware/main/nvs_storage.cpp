#include "nvs_storage.hpp"

#include "nvs.h"
#include "nvs_flash.h"

namespace fg {
namespace {
constexpr char kNamespace[] = "finger_gate";

StoreResult result(esp_err_t error)
{
    if (error == ESP_OK) return StoreResult::Ok;
    if (error == ESP_ERR_NVS_NOT_FOUND) return StoreResult::NotFound;
    if (error == ESP_ERR_NVS_INVALID_LENGTH || error == ESP_ERR_NVS_INVALID_HANDLE) return StoreResult::Corrupt;
    return StoreResult::Failed;
}
}

StoreResult NvsKeyValueStore::initialize()
{
    return result(nvs_flash_init());
}

StoreResult NvsKeyValueStore::get(const std::string& key, std::vector<uint8_t>* value) const
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(kNamespace, NVS_READONLY, &handle);
    if (error != ESP_OK) return result(error);
    size_t size = 0;
    error = nvs_get_blob(handle, key.c_str(), nullptr, &size);
    if (error == ESP_OK) {
        value->resize(size);
        error = nvs_get_blob(handle, key.c_str(), value->data(), &size);
    }
    nvs_close(handle);
    return result(error);
}

StoreResult NvsKeyValueStore::put(const std::string& key, const std::vector<uint8_t>& value)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(kNamespace, NVS_READWRITE, &handle);
    if (error == ESP_OK) error = nvs_set_blob(handle, key.c_str(), value.data(), value.size());
    if (error == ESP_OK) error = nvs_commit(handle);
    if (handle != 0) nvs_close(handle);
    return result(error);
}

StoreResult NvsKeyValueStore::erase(const std::string& key)
{
    nvs_handle_t handle = 0;
    esp_err_t error = nvs_open(kNamespace, NVS_READWRITE, &handle);
    if (error == ESP_OK) error = nvs_erase_key(handle, key.c_str());
    if (error == ESP_OK) error = nvs_commit(handle);
    if (handle != 0) nvs_close(handle);
    return result(error);
}

}
