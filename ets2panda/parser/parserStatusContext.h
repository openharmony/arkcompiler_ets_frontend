/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef PARSER_STATUS_CONTEXT_H
#define PARSER_STATUS_CONTEXT_H

#include "parserImpl.h"

namespace ark::es2panda::parser {

template <ParserStatus STATUS>
class SavedStatusContext {
public:
    explicit SavedStatusContext(ParserContext *ctx)
        // NOLINTNEXTLINE(readability-magic-numbers)
        : ctx_(ctx), savedStatus_(static_cast<ParserStatus>(ctx->Status() & STATUS))
    {
        // NOLINTNEXTLINE(readability-magic-numbers)
        ctx->Status() |= STATUS;
    }

    NO_COPY_SEMANTIC(SavedStatusContext);
    NO_MOVE_SEMANTIC(SavedStatusContext);

    ~SavedStatusContext()
    {
        if (savedStatus_ == ParserStatus::NO_OPTS) {
            ctx_->Status() &= ~savedStatus_;
        }
    }

private:
    ParserContext *ctx_;
    ParserStatus savedStatus_;
};

class SwitchContext : public SavedStatusContext<ParserStatus::IN_SWITCH> {
public:
    explicit SwitchContext(ParserContext *ctx) : SavedStatusContext(ctx) {}
    NO_COPY_SEMANTIC(SwitchContext);
    NO_MOVE_SEMANTIC(SwitchContext);
    ~SwitchContext() = default;
};

class IterationContext : public SavedStatusContext<ParserStatus::IN_ITERATION> {
public:
    explicit IterationContext(ParserContext *ctx) : SavedStatusContext(ctx) {}

    NO_COPY_SEMANTIC(IterationContext);
    NO_MOVE_SEMANTIC(IterationContext);
    ~IterationContext() = default;
};

class FunctionParameterContext : public SavedStatusContext<ParserStatus::FUNCTION_PARAM> {
public:
    explicit FunctionParameterContext(ParserContext *ctx) : SavedStatusContext(ctx) {}

    NO_COPY_SEMANTIC(FunctionParameterContext);
    NO_MOVE_SEMANTIC(FunctionParameterContext);
    ~FunctionParameterContext() = default;
};

class SavedParserContext {
public:
    template <typename... Args>
    explicit SavedParserContext(ParserImpl *parser, Args &&...args) : parser_(parser), prev_(parser->context_)
    {
        parser_->context_ = ParserContext(&prev_, std::forward<Args>(args)...);
    }

    NO_COPY_SEMANTIC(SavedParserContext);
    DEFAULT_MOVE_SEMANTIC(SavedParserContext);

    ~SavedParserContext()
    {
        parser_->context_ = prev_;
    }

private:
    ParserImpl *parser_;
    ParserContext prev_;
};

class SavedClassPrivateContext {
public:
    explicit SavedClassPrivateContext(ParserImpl *parser) : parser_(parser), prev_(parser->classPrivateContext_)
    {
        parser_->classPrivateContext_ = ClassPrivateContext(&prev_);
    }

    NO_COPY_SEMANTIC(SavedClassPrivateContext);
    DEFAULT_MOVE_SEMANTIC(SavedClassPrivateContext);

    ~SavedClassPrivateContext()
    {
        parser_->classPrivateContext_ = prev_;
    }

private:
    ParserImpl *parser_;
    ClassPrivateContext prev_;
};

class FunctionContext : public SavedParserContext {
public:
    explicit FunctionContext(ParserImpl *parser, ParserStatus newStatus) : SavedParserContext(parser, newStatus)
    {
        if ((newStatus & ParserStatus::GENERATOR_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::GENERATOR;
        }

        if ((newStatus & ParserStatus::ASYNC_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::ASYNC;
        }

        if ((newStatus & ParserStatus::CONSTRUCTOR_FUNCTION) != 0) {
            flags_ |= ir::ScriptFunctionFlags::CONSTRUCTOR;
        }
    }

    ir::ScriptFunctionFlags Flags() const
    {
        return flags_;
    }

    bool IsAsync() const
    {
        return (flags_ & ir::ScriptFunctionFlags::ASYNC) != 0;
    }

    void AddFlag(ir::ScriptFunctionFlags flags)
    {
        flags_ |= flags;
    }

    NO_COPY_SEMANTIC(FunctionContext);
    NO_MOVE_SEMANTIC(FunctionContext);
    ~FunctionContext() = default;

private:
    ir::ScriptFunctionFlags flags_ {ir::ScriptFunctionFlags::NONE};
};

class ArrowFunctionContext : public FunctionContext {
public:
    explicit ArrowFunctionContext(ParserImpl *parser, bool isAsync)
        : FunctionContext(parser, InitialFlags(parser->context_.Status()))
    {
        if (isAsync) {
            AddFlag(ir::ScriptFunctionFlags::ASYNC);
        }

        AddFlag(ir::ScriptFunctionFlags::ARROW);
    }

    NO_COPY_SEMANTIC(ArrowFunctionContext);
    NO_MOVE_SEMANTIC(ArrowFunctionContext);
    ~ArrowFunctionContext() = default;

private:
    static ParserStatus InitialFlags(ParserStatus currentStatus)
    {
        return ParserStatus::FUNCTION | ParserStatus::ARROW_FUNCTION |
               static_cast<ParserStatus>(currentStatus & (ParserStatus::ALLOW_SUPER | ParserStatus::ALLOW_SUPER_CALL));
    }
};
}  // namespace ark::es2panda::parser
#endif
