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
#include "plugin.h"
#include "os/library_loader.h"

namespace panda::es2panda::util {

std::string Plugin::FullNameForProcedure(std::string const &short_name)
{
    return std::string(name_.Utf8()) + "_" + short_name;
}

Plugin::Plugin(util::StringView const &name) : name_ {name}, err_ {0}, h_ {nullptr}
{
    std::string so_name =
        os::library_loader::DYNAMIC_LIBRARY_PREFIX + std::string(name) + os::library_loader::DYNAMIC_LIBRARY_SUFFIX;
    if (auto load_res = os::library_loader::Load(so_name); load_res.HasValue()) {
        h_ = std::move(load_res.Value());
    } else {
        err_ = load_res.Error();
        ok_ = false;
    }

    if (auto init_res = os::library_loader::ResolveSymbol(h_, FullNameForProcedure("Initialize"));
        init_res.HasValue()) {
        initialize_ = reinterpret_cast<void (*)()>(init_res.Value());
    }

    if (auto ap_res = os::library_loader::ResolveSymbol(h_, FullNameForProcedure("AfterParse")); ap_res.HasValue()) {
        after_parse_ = reinterpret_cast<void (*)(es2panda_Context *)>(ap_res.Value());
    }

    if (auto ac_res = os::library_loader::ResolveSymbol(h_, FullNameForProcedure("AfterCheck")); ac_res.HasValue()) {
        after_check_ = reinterpret_cast<void (*)(es2panda_Context *)>(ac_res.Value());
    }

    if (auto al_res = os::library_loader::ResolveSymbol(h_, FullNameForProcedure("AfterLowerings"));
        al_res.HasValue()) {
        after_lowerings_ = reinterpret_cast<void (*)(es2panda_Context *)>(al_res.Value());
    }
}

}  // namespace panda::es2panda::util
