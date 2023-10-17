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

#ifndef ES2PANDA_COMPILER_INCLUDE_COMPILER_IMPL_H
#define ES2PANDA_COMPILER_INCLUDE_COMPILER_IMPL_H

#include "es2panda.h"
#include "compiler/core/compileQueue.h"
#include "macros.h"
#include "mem/arena_allocator.h"
#include "os/thread.h"

#include <string>

namespace panda::pandasm {
struct Program;
}  // namespace panda::pandasm

namespace panda::es2panda::compiler {
class CompileQueue;
class CompilerContext;

class CompilationUnit {
public:
    explicit CompilationUnit(const SourceFile &i, const CompilerOptions &o, uint32_t s, ScriptExtension e)
        : input(i), options(o), raw_parser_status(s), ext(e)
    {
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    const SourceFile &input;
    const CompilerOptions &options;
    uint32_t raw_parser_status;
    ScriptExtension ext;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class CompilerImpl {
public:
    explicit CompilerImpl(size_t thread_count) : queue_(thread_count) {}
    NO_COPY_SEMANTIC(CompilerImpl);
    NO_MOVE_SEMANTIC(CompilerImpl);
    ~CompilerImpl() = default;

    pandasm::Program *Compile(const CompilationUnit &unit);

    static void DumpAsm(const panda::pandasm::Program *prog);

private:
    panda::pandasm::Program *Emit(CompilerContext *context);
    static void HandleContextLiterals(CompilerContext *context);

    CompileQueue queue_;
};
}  // namespace panda::es2panda::compiler

#endif
