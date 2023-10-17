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

#ifndef ES2PANDA_COMPILER_CORE_COMPILER_CONTEXT_H
#define ES2PANDA_COMPILER_CORE_COMPILER_CONTEXT_H

#include "macros.h"
#include "mem/arena_allocator.h"
#include "es2panda.h"
#include "compiler/base/literals.h"

#include <cstdint>
#include <mutex>

namespace panda::es2panda::binder {
class Binder;
class FunctionScope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
class Checker;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::compiler {
class Literal;
class DebugInfo;
class Emitter;
class CodeGen;
class ProgramElement;

class CompilerContext {
public:
    using CodeGenCb =
        std::function<void(compiler::CompilerContext *context, binder::FunctionScope *, compiler::ProgramElement *)>;

    CompilerContext(binder::Binder *binder, checker::Checker *checker, CompilerOptions options, CodeGenCb code_gen_cb)
        : binder_(binder), checker_(checker), options_(std::move(options)), code_gen_cb_(std::move(code_gen_cb))
    {
    }

    NO_COPY_SEMANTIC(CompilerContext);
    NO_MOVE_SEMANTIC(CompilerContext);
    ~CompilerContext() = default;

    binder::Binder *Binder() const
    {
        return binder_;
    }

    checker::Checker *Checker() const
    {
        return checker_;
    }

    Emitter *GetEmitter() const
    {
        return emitter_;
    }

    void SetEmitter(Emitter *emitter)
    {
        emitter_ = emitter;
    }

    const CodeGenCb &GetCodeGenCb() const
    {
        return code_gen_cb_;
    }

    int32_t AddContextLiteral(LiteralBuffer &&literals)
    {
        buff_storage_.emplace_back(std::move(literals));
        return buff_storage_.size() - 1;
    }

    const std::vector<LiteralBuffer> &ContextLiterals() const
    {
        return buff_storage_;
    }

    const CompilerOptions *Options() const
    {
        return &options_;
    }

    bool IsDebug() const
    {
        return options_.is_debug;
    }

    bool DumpDebugInfo() const
    {
        return options_.dump_debug_info;
    }

    bool IsDirectEval() const
    {
        return options_.is_direct_eval;
    }

    bool IsFunctionEval() const
    {
        return options_.is_function_eval;
    }

    bool IsEval() const
    {
        return options_.is_eval;
    }

private:
    binder::Binder *binder_;
    checker::Checker *checker_;
    Emitter *emitter_ {};
    std::vector<LiteralBuffer> buff_storage_;
    CompilerOptions options_;
    CodeGenCb code_gen_cb_ {};
};
}  // namespace panda::es2panda::compiler

#endif
