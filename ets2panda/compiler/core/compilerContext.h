/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include <mutex>

#include "es2panda.h"
#include "compiler/base/literals.h"
#include "parser/parserImpl.h"

namespace ark::es2panda::varbinder {
class VarBinder;
class FunctionScope;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::checker {
class Checker;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::compiler {
class Literal;
class DebugInfo;
class Emitter;
class CodeGen;
class ProgramElement;
class AstCompiler;

class CompilerContext final {
public:
    using CodeGenCb =
        std::function<void(compiler::CompilerContext *context, varbinder::FunctionScope *, compiler::ProgramElement *)>;

    CompilerContext(varbinder::VarBinder *varbinder, checker::Checker *checker, CompilerOptions options,
                    CodeGenCb codeGenCb)
        : varbinder_(varbinder), checker_(checker), options_(std::move(options)), codeGenCb_(std::move(codeGenCb))
    {
    }

    CompilerContext() = delete;
    NO_COPY_SEMANTIC(CompilerContext);
    NO_MOVE_SEMANTIC(CompilerContext);
    ~CompilerContext() = default;

    [[nodiscard]] varbinder::VarBinder *VarBinder() const noexcept
    {
        return varbinder_;
    }

    [[nodiscard]] checker::Checker *Checker() const noexcept
    {
        return checker_;
    }

    [[nodiscard]] parser::ParserImpl *GetParser() const noexcept
    {
        return parser_;
    }

    void SetParser(parser::ParserImpl *const parser) noexcept
    {
        parser_ = parser;
    }

    [[nodiscard]] Emitter *GetEmitter() const noexcept
    {
        return emitter_;
    }

    void SetEmitter(Emitter *emitter) noexcept
    {
        emitter_ = emitter;
    }

    [[nodiscard]] const CodeGenCb &GetCodeGenCb() const noexcept
    {
        return codeGenCb_;
    }

    [[nodiscard]] uint32_t AddContextLiteral(LiteralBuffer &&literals)
    {
        buffStorage_.emplace_back(std::move(literals));
        return buffStorage_.size() - 1;
    }

    [[nodiscard]] const std::vector<LiteralBuffer> &ContextLiterals() const noexcept
    {
        return buffStorage_;
    }

    [[nodiscard]] const CompilerOptions *Options() const noexcept
    {
        return &options_;
    }

    [[nodiscard]] bool IsDebug() const noexcept
    {
        return options_.isDebug;
    }

    [[nodiscard]] bool DumpDebugInfo() const noexcept
    {
        return options_.dumpDebugInfo;
    }

    [[nodiscard]] bool IsDirectEval() const noexcept
    {
        return options_.isDirectEval;
    }

    [[nodiscard]] bool IsFunctionEval() const noexcept
    {
        return options_.isFunctionEval;
    }

    [[nodiscard]] bool IsEval() const noexcept
    {
        return options_.isEval;
    }

private:
    varbinder::VarBinder *varbinder_;
    checker::Checker *checker_;
    parser::ParserImpl *parser_ = nullptr;
    Emitter *emitter_ {};
    std::vector<LiteralBuffer> buffStorage_;
    CompilerOptions options_;
    CodeGenCb codeGenCb_ {};
};
}  // namespace ark::es2panda::compiler

#endif
