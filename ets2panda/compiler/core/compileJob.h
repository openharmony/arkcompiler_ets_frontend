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

#ifndef ES2PANDA_COMPILER_CORE_COMPILE_JOB_H
#define ES2PANDA_COMPILER_CORE_COMPILE_JOB_H

#include "macros.h"
#include "es2panda.h"
#include "compiler/core/programElement.h"

#include <condition_variable>
#include <mutex>

namespace panda::es2panda::binder {
class FunctionScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::compiler {
class CompilerContext;
class ProgramElement;

class CompileJob {
public:
    CompileJob() = default;
    NO_COPY_SEMANTIC(CompileJob);
    NO_MOVE_SEMANTIC(CompileJob);
    ~CompileJob() = default;

    const ProgramElement *GetProgramElement() const
    {
        return &program_element_;
    }

    ProgramElement *GetProgramElement()
    {
        return &program_element_;
    }

    void SetContext(CompilerContext *context, binder::FunctionScope *scope)
    {
        context_ = context;
        scope_ = scope;
    }

    void Run();
    void DependsOn(CompileJob *job);
    void Signal();

private:
    std::mutex m_;
    std::condition_variable cond_;
    CompilerContext *context_ {};
    binder::FunctionScope *scope_ {};
    ProgramElement program_element_;
    CompileJob *dependant_ {};
    size_t dependencies_ {0};
};
}  // namespace panda::es2panda::compiler

#endif
