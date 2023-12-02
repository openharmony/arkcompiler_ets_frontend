/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef ES2PANDA_UTIL_PLUGINS_H
#define ES2PANDA_UTIL_PLUGINS_H

#include "macros.h"
#include "os/library_loader.h"
#include "public/es2panda_lib.h"
#include "util/ustring.h"

namespace panda::es2panda::util {

class Plugin {
public:
    explicit Plugin(util::StringView const &name);
    ~Plugin() = default;

    NO_COPY_SEMANTIC(Plugin);
    DEFAULT_MOVE_SEMANTIC(Plugin);

    bool IsOk()
    {
        return ok_;
    }

    os::Error Error()
    {
        return err_;
    }

    void Initialize() const
    {
        if (initialize_ != nullptr) {
            initialize_();
        }
    }

    void AfterParse(es2panda_Context *context) const
    {
        if (after_parse_ != nullptr) {
            after_parse_(context);
        }
    }

    void AfterCheck(es2panda_Context *context) const
    {
        if (after_check_ != nullptr) {
            after_check_(context);
        }
    }

    void AfterLowerings(es2panda_Context *context) const
    {
        if (after_lowerings_ != nullptr) {
            after_lowerings_(context);
        }
    }

private:
    std::string FullNameForProcedure(std::string const &short_name);

    util::StringView name_;
    bool ok_ {true};
    os::Error err_;
    os::library_loader::LibraryHandle h_;

    void (*initialize_)() = nullptr;
    void (*after_parse_)(es2panda_Context *) = nullptr;
    void (*after_check_)(es2panda_Context *) = nullptr;
    void (*after_lowerings_)(es2panda_Context *) = nullptr;
};

}  // namespace panda::es2panda::util

#endif
