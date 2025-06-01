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

#ifndef TS_TYPES_H
#define TS_TYPES_H

#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include "securec.h"

// NOLINTBEGIN

struct KStringPtrImpl {
    KStringPtrImpl(const char *str) : value(nullptr), owned(true)
    {
        int len = str ? strlen(str) : 0;
        assign(str, len);
    }
    KStringPtrImpl(const char *str, int len, bool isOwned) : value(nullptr), owned(isOwned)
    {
        assign(str, len);
    }
    KStringPtrImpl() : value(nullptr), lengthStr(0), owned(true) {}

    KStringPtrImpl(const KStringPtrImpl &other) = delete;
    KStringPtrImpl &operator=(const KStringPtrImpl &other) = delete;

    KStringPtrImpl(KStringPtrImpl &&other)
    {
        this->value = other.release();
        this->owned = other.owned;
        other.owned = false;
        this->lengthStr = other.lengthStr;
    }

    ~KStringPtrImpl()
    {
        if (value && owned)
            free(value);
    }

    bool isNull() const
    {
        return value == nullptr;
    }
    const char *c_str() const
    {
        return value;
    }
    char *data() const
    {
        return value;
    }
    int length() const
    {
        return lengthStr;
    }

    void resize(unsigned int size)
    {
        lengthStr = size;
        if (!owned)
            return;
        // Ignore old content.
        if (value && owned)
            free(value);
        value = reinterpret_cast<char *>(std::malloc(size + 1));
        if (value == nullptr) {
            // NOTE(khil): should be refactored to proper malloc
            return;
        }
        value[size] = 0;
    }

    void assign(const char *data)
    {
        assign(data, data ? strlen(data) : 0);
    }

    void assign(const char *data, unsigned int len)
    {
        if (value && owned)
            free(value);
        if (data) {
            if (owned) {
                value = reinterpret_cast<char *>(std::malloc(len + 1));
                if (!value) {
                    return;
                }
                memcpy_s(value, len, data, len);
                value[len] = 0;
            } else {
                value = const_cast<char *>(data);
            }
        } else {
            value = nullptr;
        }
        lengthStr = len;
    }

protected:
    char *release()
    {
        char *result = this->value;
        this->value = nullptr;
        return result;
    }

private:
    char *value;
    int lengthStr;
    bool owned;
};

struct KInteropNumber {
    int8_t tag;
    union {
        int32_t i32;
        float f32;
    };
    static inline KInteropNumber fromDouble(double value)
    {
        KInteropNumber result = {0, {0}};
        // NOTE(khil): boundary check
        if (value == std::floor(value)) {
            result.tag = 102U;  // ARK_TAG_INT32
            result.i32 = (int)value;
        } else {
            result.tag = 103U;  // ARK_TAG_FLOAT32
            result.f32 = (float)value;
        }
        return result;
    }
    inline double asDouble()
    {
        if (tag == 102U)  // ARK_TAG_INT32
            return (double)i32;
        else
            return (double)f32;
    }
};

typedef int8_t KBoolean;
typedef uint8_t KByte;
typedef int16_t KChar;
typedef int16_t KShort;
typedef uint16_t KUShort;
typedef int32_t KInt;
typedef uint32_t KUInt;
typedef float KFloat;
typedef int64_t KLong;
typedef double KDouble;
typedef void *KNativePointer;
typedef KStringPtrImpl KStringPtr;
typedef float *KFloatArray;
typedef const uint8_t *KStringArray;
typedef void **KNativePointerArray;

struct KInteropBuffer {
    KLong length;
    KNativePointer data;

    KInt resourceId;
    void (*dispose)(KInt /* resourceId for now */);
};

struct KInteropReturnBuffer {
    KInt length;
    KNativePointer data;
    void (*dispose)(KNativePointer data, KInt length);
};

struct KLength {
    KByte type;
    KFloat value;
    KInt unit;
    KInt resource;
};

// CC-OFFNXT(G.FUD.06) switch-case, ODR
inline void ParseKLength(const KStringPtrImpl &string, KLength *result)
{
    char *suffixPtr = nullptr;

    float value = std::strtof(string.c_str(), &suffixPtr);

    if (!suffixPtr || suffixPtr == string.c_str()) {
        // not a numeric value
        result->unit = -1;
        return;
    }
    result->value = value;
    if (suffixPtr[0] == '\0' || (suffixPtr[0] == 'v' && suffixPtr[1] == 'p')) {
        result->unit = 1;
    } else if (suffixPtr[0] == '%') {
        result->unit = 3U;
    } else if (suffixPtr[0] == 'p' && suffixPtr[1] == 'x') {
        result->unit = 0;
    } else if (suffixPtr[0] == 'l' && suffixPtr[1] == 'p' && suffixPtr[2U] == 'x') {
        result->unit = 4U;
    } else if (suffixPtr[0] == 'f' && suffixPtr[1] == 'p') {
        result->unit = 2U;
    } else {
        result->unit = -1;
    }
}

struct KVMContextRaw;
typedef KVMContextRaw *KVMContext;

// BEWARE: this MUST never be used in user code, only in very rare service code.
struct KVMObjectRaw;
typedef KVMObjectRaw *KVMObjectHandle;

typedef struct KVMDeferred {
    void *handler;
    void *context;
    void (*resolve)(KVMDeferred *thiz, uint8_t *data, int32_t length);
    void (*reject)(KVMDeferred *thiz, const char *message);
} KVMDeferred;

template <class T>
T *ptr(KNativePointer ptr)
{
    return reinterpret_cast<T *>(ptr);
}

template <class T>
T &ref(KNativePointer ptr)
{
    return *reinterpret_cast<T *>(ptr);
}

inline KNativePointer NativePtr(void *pointer)
{
    return reinterpret_cast<KNativePointer>(pointer);
}

template <class T>
KNativePointer fnPtr(void (*pointer)(T *))
{
    return reinterpret_cast<KNativePointer>(pointer);
}

// NOLINTEND

#endif /* TS_TYPES_H */
