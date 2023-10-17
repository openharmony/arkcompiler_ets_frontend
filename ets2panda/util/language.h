/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_DYNAMIC_LANGUAGE_H
#define ES2PANDA_DYNAMIC_LANGUAGE_H

#include <array>
#include <optional>
#include <string_view>

#include "libpandabase/macros.h"

namespace panda::es2panda {

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define LANGUAGES(_)   \
    _(AS, "as", false) \
    _(JS, "js", true)  \
    _(TS, "ts", true)  \
    _(ETS, "ets", false)

class Language {
public:
    enum class Id {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TO_ENUM(e, s, d) e,
        LANGUAGES(TO_ENUM)
#undef TO_ENUM
            COUNT
    };

    constexpr explicit Language(Id id) : id_(id) {}

    constexpr std::string_view ToString() const
    {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TO_STR(e, s, d) \
    if (id_ == Id::e) { \
        return s;       \
    }
        LANGUAGES(TO_STR)
#undef TO_STR
        UNREACHABLE();
    }

    static std::optional<Language> FromString(std::string_view str)
    {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FROM_STR(e, s, d)       \
    if (str == s) {             \
        return Language(Id::e); \
    }
        LANGUAGES(FROM_STR)
#undef FROM_STR
        return {};
    }

    Id GetId() const
    {
        return id_;
    }

    bool IsDynamic() const
    {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TO_DYN(e, s, d) \
    if (id_ == Id::e) { \
        return d;       \
    }
        LANGUAGES(TO_DYN)
#undef TO_DYN
        UNREACHABLE();
    }

    bool operator==(const Language &l) const
    {
        return id_ == l.id_;
    }

    bool operator!=(const Language &l) const
    {
        return id_ != l.id_;
    }

private:
    static constexpr auto COUNT = static_cast<size_t>(Id::COUNT);

public:
    static std::array<Language, COUNT> All()
    {
        return {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TO_LANG(e, s, d) Language(Id::e),
            LANGUAGES(TO_LANG)
#undef TO_LANG
        };
    }

private:
    Id id_;
};

}  // namespace panda::es2panda

// NOLINTNEXTLINE(cert-dcl58-cpp)
namespace std {

template <>
// NOLINTNEXTLINE(altera-struct-pack-align)
struct hash<panda::es2panda::Language> {
    std::size_t operator()(panda::es2panda::Language lang) const
    {
        return std::hash<panda::es2panda::Language::Id> {}(lang.GetId());
    }
};

}  // namespace std

#endif  // ES2PANDA_DYNAMIC_LANGUAGE_H
