/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_PLUGIN_PHASE_H
#define ES2PANDA_COMPILER_PLUGIN_PHASE_H

#include "compiler/lowering/phase.h"
#include "util/plugin.h"

namespace panda::es2panda::compiler {

class PluginPhase : public Phase {
public:
    constexpr PluginPhase(char const *name, es2panda_ContextState context_state,
                          void (util::Plugin::*method_call)(es2panda_Context *) const) noexcept
        : name_(name), context_state_(context_state), method_call_(method_call)
    {
    }

    std::string_view Name() override
    {
        return name_;
    }

    bool Perform(public_lib::Context *ctx, parser::Program *program) override;

private:
    char const *name_;
    es2panda_ContextState context_state_;
    void (util::Plugin::*method_call_)(es2panda_Context *) const;
};

}  // namespace panda::es2panda::compiler

#endif
