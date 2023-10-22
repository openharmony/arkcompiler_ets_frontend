/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_CORE_PARSER_PRIVATE_CONTEXT_H
#define ES2PANDA_PARSER_CORE_PARSER_PRIVATE_CONTEXT_H

#include "macros.h"
#include "util/enumbitops.h"
#include "util/language.h"
#include "util/ustring.h"

#include <vector>

namespace panda::es2panda::parser {
class Program;

enum class ParserStatus : uint32_t {
    NO_OPTS = 0U,
    DIRECT_EVAL = 1U << 0U,

    FUNCTION = 1U << 1U,
    ARROW_FUNCTION = 1U << 2U,
    GENERATOR_FUNCTION = 1U << 3U,
    ASYNC_FUNCTION = 1U << 4U,
    CONSTRUCTOR_FUNCTION = 1U << 5U,
    FUNCTION_PARAM = 1U << 6U,
    IS_SPREAD = 1U << 7U,
    ACCESSOR_FUNCTION = 1U << 8U,
    FUNCTION_DECLARATION = 1U << 9U,

    ALLOW_SUPER = 1U << 10U,
    ALLOW_SUPER_CALL = 1U << 11U,

    IN_ITERATION = 1U << 14U,
    IN_LABELED = 1U << 15U,

    EXPORT_DEFAULT_REACHED = 1U << 16U,
    HAS_COMPLEX_PARAM = 1U << 17U,
    IN_SWITCH = 1U << 18U,

    MODULE = 1U << 19U,
    ALLOW_NEW_TARGET = 1U << 20U,

    IN_EXTENDS = 1U << 21U,
    ALLOW_THIS_TYPE = 1U << 22U,
    IN_METHOD_DEFINITION = 1U << 23U,
    IN_AMBIENT_CONTEXT = 1U << 24U,
    IN_CLASS_BODY = 1U << 25U,
    NEED_RETURN_TYPE = 1U << 26U,

    IN_EXTERNAL = 1U << 27U,
    IN_IMPORT = 1U << 28U,
    IN_DEFAULT_IMPORTS = 1U << 29U,
    IN_EXTENSION_FUNCTION = 1U << 30U,
};

DEFINE_BITOPS(ParserStatus)

class ParserContext {
public:
    explicit ParserContext(const Program *program, ParserStatus status);

    explicit ParserContext(ParserContext *current, ParserStatus new_status, util::StringView label = "")
        : program_(current->program_), prev_(current), label_(label), lang_(current->lang_)
    {
        ParserStatus current_status = current->status_;
        current_status &= (ParserStatus::MODULE | ParserStatus::ALLOW_NEW_TARGET | ParserStatus::IN_EXTENDS |
                           ParserStatus::ALLOW_THIS_TYPE | ParserStatus::IN_CLASS_BODY | ParserStatus::FUNCTION |
                           ParserStatus::IN_AMBIENT_CONTEXT);
        status_ = current_status | new_status;
    }

    DEFAULT_COPY_SEMANTIC(ParserContext);
    DEFAULT_MOVE_SEMANTIC(ParserContext);
    ~ParserContext() = default;

    const Program *GetProgram() const
    {
        return program_;
    }

    void SetProgram(Program *program)
    {
        program_ = program;
    }

    Language GetLanguge() const
    {
        return lang_;
    }

    Language SetLanguage(Language lang)
    {
        auto res = lang_;
        lang_ = lang;
        return res;
    }

    ParserContext *Prev() const
    {
        return prev_;
    }

    const ParserStatus &Status() const
    {
        return status_;
    }

    ParserStatus &Status()
    {
        return status_;
    }

    bool IsGenerator() const
    {
        return (status_ & ParserStatus::GENERATOR_FUNCTION) != 0;
    }

    bool IsFunctionOrParam() const
    {
        return (status_ & (ParserStatus::FUNCTION | ParserStatus::FUNCTION_PARAM)) != 0;
    }

    bool IsAsync() const
    {
        return (status_ & ParserStatus::ASYNC_FUNCTION) != 0;
    }

    bool IsModule() const
    {
        return (status_ & ParserStatus::MODULE) != 0;
    }

    bool IsDynamic() const
    {
        return lang_.IsDynamic();
    }

    const ParserContext *FindLabel(const util::StringView &label) const;

private:
    const Program *program_;
    ParserContext *prev_ {};
    ParserStatus status_ {};
    util::StringView label_ {};
    Language lang_;
};
}  // namespace panda::es2panda::parser

#endif
