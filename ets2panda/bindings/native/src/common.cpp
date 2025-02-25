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

#include "common.h"
#include <string>
#include "public/es2panda_lib.h"

// NOLINTBEGIN

std::string GetString(KStringPtr ptr)
{
    return ptr.data();
}

char *GetStringCopy(KStringPtr &ptr)
{
    return strdup(ptr.c_str());
}

inline KUInt UnpackUInt(const KByte *bytes)
{
    return (bytes[0] | (bytes[1] << 8U) | (bytes[2U] << 16U) | (bytes[3U] << 24U));
}

KNativePointer impl_CreateConfig(KInt argc, KStringArray argvPtr)
{
    const std::size_t HEADER_LEN = 4;

    const char **argv = new const char *[static_cast<unsigned int>(argc)];
    std::size_t position = HEADER_LEN;
    std::size_t strLen;
    for (std::size_t i = 0; i < static_cast<std::size_t>(argc); ++i) {
        strLen = UnpackUInt(argvPtr + position);
        position += HEADER_LEN;
        argv[i] = strdup(std::string(reinterpret_cast<const char *>(argvPtr + position), strLen).c_str());
        position += strLen;
    }
    return es2panda_GetImpl(ES2PANDA_LIB_VERSION)->CreateConfig(argc, argv);
}
TS_INTEROP_2(CreateConfig, KNativePointer, KInt, KStringArray)

KNativePointer impl_DestroyConfig(KNativePointer configPtr)
{
    auto config = reinterpret_cast<es2panda_Config *>(configPtr);
    es2panda_GetImpl(ES2PANDA_LIB_VERSION)->DestroyConfig(config);
    return nullptr;
}
TS_INTEROP_1(DestroyConfig, KNativePointer, KNativePointer)

KNativePointer impl_DestroyContext(KNativePointer contextPtr)
{
    auto context = reinterpret_cast<es2panda_Context *>(contextPtr);
    es2panda_GetImpl(ES2PANDA_LIB_VERSION)->DestroyContext(context);
    return nullptr;
}
TS_INTEROP_1(DestroyContext, KNativePointer, KNativePointer)

// NOLINTEND
