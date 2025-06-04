/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstddef>
#include <string>
#include <variant>
#include <vector>
#include <map>
#include <securec.h>

// NOLINTBEGIN

#ifdef TS_INTEROP_MODULE
#undef TS_INTEROP_MODULE
#endif

#define TS_INTEROP_MODULE InteropNativeModule
#include "interop-logging.h"
#include "convertors-napi.h"
#include "common-interop.h"

#if TS_INTEROP_PROFILER
#include "profiler.h"

InteropProfiler *InteropProfiler::_instance = nullptr;

#endif

using std::string;

// Callback dispatcher MOVED to convertors-napi.cc.
// Let's keep platform-specific parts of the code together

typedef void (*HoldT)(KInt);

KInt impl_getTypeOfVariant(KNativePointer varPtr)
{
    auto *var = reinterpret_cast<std::variant<int, std::string> *>(varPtr);
    if (std::get_if<int>(var) != nullptr) {
        return 0;
    } else {
        return 1;
    }
}
TS_INTEROP_1(getTypeOfVariant, KInt, KNativePointer)

KNativePointer impl_getStringFromVariant(KNativePointer varPtr)
{
    auto *var = reinterpret_cast<std::variant<int, std::string> *>(varPtr);
    auto *res = new std::string(*std::get_if<std::string>(var));
    return res;
}
TS_INTEROP_1(getStringFromVariant, KNativePointer, KNativePointer)

KInt impl_getIntFromVariant(KNativePointer varPtr)
{
    auto *var = reinterpret_cast<std::variant<int, std::string> *>(varPtr);
    auto res = *std::get_if<int>(var);
    return res;
}
TS_INTEROP_1(getIntFromVariant, KInt, KNativePointer)

KInteropBuffer impl_MaterializeBuffer(KNativePointer data, KLong length, KInt resourceId, KNativePointer holdPtr,
                                      KNativePointer releasePtr)
{
    auto hold = reinterpret_cast<void (*)(KInt)>(holdPtr);
    auto release = reinterpret_cast<void (*)(KInt)>(releasePtr);
    hold(resourceId);
    return KInteropBuffer {length, data, resourceId, release};
}
TS_INTEROP_5(MaterializeBuffer, KInteropBuffer, KNativePointer, KLong, KInt, KNativePointer, KNativePointer)

KNativePointer impl_GetNativeBufferPointer(KInteropBuffer buffer)
{
    return buffer.data;
}
TS_INTEROP_1(GetNativeBufferPointer, KNativePointer, KInteropBuffer)

KInt impl_StringLength(KNativePointer ptr)
{
    auto *s = reinterpret_cast<string *>(ptr);
    return s->length();
}
TS_INTEROP_1(StringLength, KInt, KNativePointer)

void impl_StringData(KNativePointer ptr, KByte *bytes, KUInt size)
{
    auto *s = reinterpret_cast<string *>(ptr);
    if (s != nullptr) {
        memcpy_s(bytes, size, s->c_str(), size);
    }
}
TS_INTEROP_V3(StringData, KNativePointer, KByte *, KUInt)

KNativePointer impl_StringMake(const KStringPtr &str)
{
    return new string(str.c_str());
}
TS_INTEROP_1(StringMake, KNativePointer, KStringPtr)

// For slow runtimes w/o fast encoders.
KInt impl_ManagedStringWrite(const KStringPtr &str, KByte *buffer, KInt offset)
{
    memcpy_s(buffer + offset, str.length() + 1, str.c_str(), str.length() + 1);
    return str.length() + 1;
}
TS_INTEROP_3(ManagedStringWrite, KInt, KStringPtr, KByte *, KInt)

void stringFinalizer(string *ptr)
{
    delete ptr;
}
KNativePointer impl_GetStringFinalizer()
{
    return fnPtr<string>(stringFinalizer);
}
TS_INTEROP_0(GetStringFinalizer, KNativePointer)

void impl_InvokeFinalizer(KNativePointer obj, KNativePointer finalizer)
{
    auto finalizerF = reinterpret_cast<void (*)(KNativePointer)>(finalizer);
    finalizerF(obj);
}
TS_INTEROP_V2(InvokeFinalizer, KNativePointer, KNativePointer)

KInt impl_GetPtrVectorSize(KNativePointer ptr)
{
    auto *vec = reinterpret_cast<std::vector<void *> *>(ptr);
    return vec->size();
}
TS_INTEROP_1(GetPtrVectorSize, KInt, KNativePointer)

KNativePointer impl_GetPtrVectorElement(KNativePointer ptr, KInt index)
{
    auto vector = reinterpret_cast<std::vector<void *> *>(ptr);
    auto element = vector->at(index);
    return element;
}
TS_INTEROP_2(GetPtrVectorElement, KNativePointer, KNativePointer, KInt)

inline KUInt UnpackUInt(const KByte *bytes)
{
    return (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
}

std::vector<KStringPtr> MakeStringVector(KStringArray strArray)
{
    if (strArray == nullptr) {
        return std::vector<KStringPtr>(0);
    }
    KUInt arraySize = UnpackUInt(strArray);
    std::vector<KStringPtr> res(arraySize);
    size_t offset = sizeof(KUInt);
    for (KUInt i = 0; i < arraySize; ++i) {
        int len = UnpackUInt(strArray + offset);
        res[i].assign((const char *)(strArray + offset + sizeof(KUInt)), len);
        offset += len + sizeof(KUInt);
    }
    return res;
}

std::vector<KStringPtr> MakeStringVector(KNativePointerArray arr, KInt length)
{
    if (arr == nullptr) {
        return std::vector<KStringPtr>(0);
    } else {
        std::vector<KStringPtr> res(length);
        char **strings = reinterpret_cast<char **>(arr);
        for (KInt i = 0; i < length; ++i) {
            const char *str = reinterpret_cast<const char *>(strings[i]);
            res[i].assign(str);
        }
        return res;
    }
}

typedef KInt (*LoadVirtualMachine_t)(KInt vmKind, const char *classPath, const char *libraryPath,
                                     void *currentVMContext);
typedef KNativePointer (*StartApplication_t)(const char *appUrl, const char *appParams);
typedef KBoolean (*RunApplication_t)(const KInt arg0, const KInt arg1);
typedef void (*EmitEventT)(const KInt type, const KInt target, const KInt arg0, const KInt arg1);

static CallbackCallert g_callbackCaller = nullptr;
void setCallbackCaller(CallbackCallert callbackCaller)
{
    g_callbackCaller = callbackCaller;
}

void impl_CallCallback(KInt callbackKind, KByte *args, KInt argsSize)
{
    if (g_callbackCaller != nullptr) {
        g_callbackCaller(callbackKind, args, argsSize);
    }
}
TS_INTEROP_V3(CallCallback, KInt, KByte *, KInt)

static CallbackCallerSynct g_callbackCallerSync = nullptr;
void setCallbackCallerSync(CallbackCallerSynct callbackCallerSync)
{
    g_callbackCallerSync = callbackCallerSync;
}

void impl_CallCallbackSync(KVMContext vmContext, KInt callbackKind, KByte *args, KInt argsSize)
{
    if (g_callbackCallerSync) {
        g_callbackCallerSync(vmContext, callbackKind, args, argsSize);
    }
}
TS_INTEROP_CTX_V3(CallCallbackSync, KInt, KByte *, KInt)

void impl_CallCallbackResourceHolder(KNativePointer holder, KInt resourceId)
{
    reinterpret_cast<void (*)(KInt)>(holder)(resourceId);
}
TS_INTEROP_V2(CallCallbackResourceHolder, KNativePointer, KInt)

void impl_CallCallbackResourceReleaser(KNativePointer releaser, KInt resourceId)
{
    reinterpret_cast<void (*)(KInt)>(releaser)(resourceId);
}
TS_INTEROP_V2(CallCallbackResourceReleaser, KNativePointer, KInt)

// CC-OFFNXT(G.EXP.01) false positive
#define __QUOTE(x) #x
#define QUOTE(x) __QUOTE(x)

#ifndef INTEROP_LIBRARY_NAME
#error "INTEROP_LIBRARY_NAME must be defined"
#endif

void impl_NativeLog(const KStringPtr &str)
{
    fprintf(stdout, "%s: %s\n", QUOTE(INTEROP_LIBRARY_NAME), str.c_str());
    fflush(stdout);
}
TS_INTEROP_V1(NativeLog, KStringPtr)

int32_t callCallback(KVMContext context, int32_t methodId, uint8_t *argsData, int32_t argsLength)
{
    TS_INTEROP_CALL_INT(context, methodId, argsLength, argsData);
    return 0;
}

void resolveDeferred(KVMDeferred *deferred, [[maybe_unused]] uint8_t *argsData, [[maybe_unused]] int32_t argsLength)
{
    napi_acquire_threadsafe_function((napi_threadsafe_function)deferred->handler);
    auto status =
        napi_call_threadsafe_function((napi_threadsafe_function)deferred->handler, deferred, napi_tsfn_nonblocking);
    if (status != napi_ok)
        LOGE("cannot call thread-safe function; status=%d", status);
    napi_release_threadsafe_function((napi_threadsafe_function)deferred->handler, napi_tsfn_release);
}

void rejectDeferred(KVMDeferred *deferred, [[maybe_unused]] const char *message)
{
    napi_release_threadsafe_function((napi_threadsafe_function)deferred->handler, napi_tsfn_release);
    delete deferred;
}

void resolveDeferredImpl(napi_env env, [[maybe_unused]] napi_value js_callback, KVMDeferred *deferred,
                         [[maybe_unused]] void *data)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    auto status = napi_resolve_deferred(env, (napi_deferred)deferred->context, undefined);
    if (status != napi_ok)
        LOGE("cannot resolve deferred; status=%d", status);
    delete deferred;
}

[[maybe_unused]] static void releaseDeferred(KVMDeferred *deferred)
{
    delete deferred;
}

KVMDeferred *CreateDeferred(KVMContext vmContext, KVMObjectHandle *promiseHandle)
{
    KVMDeferred *deferred = new KVMDeferred();
    deferred->resolve = resolveDeferred;
    deferred->reject = rejectDeferred;
    // NOTE(khil): mb move\remove to interop!
    napi_env env = (napi_env)vmContext;
    napi_value promise;
    napi_value resourceName;
    size_t napiStrLen = 5;
    napi_create_string_utf8(env, "Async", napiStrLen, &resourceName);
    auto status = napi_create_promise(env, (napi_deferred *)&deferred->context, &promise);
    if (status != napi_ok)
        LOGE("cannot make a promise; status=%d", status);
    status = napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1, nullptr, nullptr, deferred,
                                             (napi_threadsafe_function_call_js)resolveDeferredImpl,
                                             (napi_threadsafe_function *)&deferred->handler);
    if (status != napi_ok)
        LOGE("cannot make threadsafe function; status=%d", status);
    *promiseHandle = (KVMObjectHandle)promise;
    return deferred;
}

// Allocate, so CTX versions.
KStringPtr impl_Utf8ToString([[maybe_unused]] KVMContext vmContext, KByte *data, KInt offset, KInt length)
{
    KStringPtr result((const char *)(data + offset), length, false);
    return result;
}
TS_INTEROP_CTX_3(Utf8ToString, KStringPtr, KByte *, KInt, KInt)

KStringPtr impl_StdStringToString([[maybe_unused]] KVMContext vmContext, KNativePointer stringPtr)
{
    auto *str = reinterpret_cast<std::string *>(stringPtr);
    KStringPtr result(str->c_str(), str->size(), false);
    return result;
}
TS_INTEROP_CTX_1(StdStringToString, KStringPtr, KNativePointer)

KInteropReturnBuffer impl_RawReturnData([[maybe_unused]] KVMContext vmContext, KInt v1, KInt v2)
{
    void *data = new int8_t[v1];
    memset_s(data, v2, v1, v2);
    KInteropReturnBuffer buffer = {v1, data, [](KNativePointer ptr, KInt) { delete[](int8_t *) ptr; }};
    return buffer;
}
TS_INTEROP_CTX_2(RawReturnData, KInteropReturnBuffer, KInt, KInt)

// NOLINTEND
