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

#include "checker.h"

#include "plugins/ecmascript/es2panda/checker/types/type.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/statements/blockStatement.h"
#include "plugins/ecmascript/es2panda/parser/program/program.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/es2panda.h"
#include "plugins/ecmascript/es2panda/checker/types/globalTypesHolder.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/unionType.h"
#include "plugins/ecmascript/es2panda/checker/types/signature.h"

#include <cstdint>
#include <initializer_list>
#include <memory>

namespace panda::es2panda::checker {
Checker::Checker()
    : allocator_(SpaceType::SPACE_TYPE_COMPILER, nullptr, true),
      context_(&allocator_, CheckerStatus::NO_OPTS),
      global_types_(allocator_.New<GlobalTypesHolder>(&allocator_)),
      relation_(allocator_.New<TypeRelation>(this))
{
}

void Checker::Initialize(binder::Binder *binder)
{
    binder_ = binder;
    scope_ = binder_->TopScope();
    program_ = binder_->Program();
}

void Checker::ThrowTypeError(std::initializer_list<TypeErrorMessageElement> list, const lexer::SourcePosition &pos)
{
    std::stringstream ss;

    for (const auto &it : list) {
        if (std::holds_alternative<char *>(it)) {
            ss << std::get<char *>(it);
        } else if (std::holds_alternative<util::StringView>(it)) {
            ss << std::get<util::StringView>(it);
        } else if (std::holds_alternative<lexer::TokenType>(it)) {
            ss << TokenToString(std::get<lexer::TokenType>(it));
        } else if (std::holds_alternative<const Type *>(it)) {
            std::get<const Type *>(it)->ToString(ss);
        } else if (std::holds_alternative<AsSrc>(it)) {
            std::get<AsSrc>(it).GetType()->ToStringAsSrc(ss);
        } else if (std::holds_alternative<size_t>(it)) {
            ss << std::to_string(std::get<size_t>(it));
        } else if (std::holds_alternative<const Signature *>(it)) {
            std::get<const Signature *>(it)->ToString(ss, nullptr, true);
        } else {
            UNREACHABLE();
        }
    }

    std::string err = ss.str();
    ThrowTypeError(err, pos);
}

void Checker::ThrowTypeError(std::string_view message, const lexer::SourcePosition &pos)
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error {ErrorType::TYPE, program_->SourceFile().Utf8(), message, loc.line, loc.col};
}

bool Checker::IsAllTypesAssignableTo(Type *source, Type *target)
{
    if (source->TypeFlags() == TypeFlag::UNION) {
        auto &types = source->AsUnionType()->ConstituentTypes();

        return std::all_of(types.begin(), types.end(),
                           [this, target](auto *it) { return IsAllTypesAssignableTo(it, target); });
    }

    return relation_->IsAssignableTo(source, target);
}

bool Checker::IsTypeIdenticalTo(Type *source, Type *target)
{
    return relation_->IsIdenticalTo(source, target);
}

bool Checker::IsTypeIdenticalTo(Type *source, Type *target, const std::string &err_msg,
                                const lexer::SourcePosition &err_pos)
{
    if (!IsTypeIdenticalTo(source, target)) {
        relation_->RaiseError(err_msg, err_pos);
    }

    return true;
}

bool Checker::IsTypeIdenticalTo(Type *source, Type *target, std::initializer_list<TypeErrorMessageElement> list,
                                const lexer::SourcePosition &err_pos)
{
    if (!IsTypeIdenticalTo(source, target)) {
        relation_->RaiseError(list, err_pos);
    }

    return true;
}

bool Checker::IsTypeAssignableTo(Type *source, Type *target)
{
    return relation_->IsAssignableTo(source, target);
}

bool Checker::IsTypeAssignableTo(Type *source, Type *target, const std::string &err_msg,
                                 const lexer::SourcePosition &err_pos)
{
    if (!IsTypeAssignableTo(source, target)) {
        relation_->RaiseError(err_msg, err_pos);
    }

    return true;
}

bool Checker::IsTypeAssignableTo(Type *source, Type *target, std::initializer_list<TypeErrorMessageElement> list,
                                 const lexer::SourcePosition &err_pos)
{
    if (!IsTypeAssignableTo(source, target)) {
        relation_->RaiseError(list, err_pos);
    }

    return true;
}

bool Checker::IsTypeComparableTo(Type *source, Type *target)
{
    return relation_->IsComparableTo(source, target);
}

bool Checker::IsTypeComparableTo(Type *source, Type *target, const std::string &err_msg,
                                 const lexer::SourcePosition &err_pos)
{
    if (!IsTypeComparableTo(source, target)) {
        relation_->RaiseError(err_msg, err_pos);
    }

    return true;
}

bool Checker::IsTypeComparableTo(Type *source, Type *target, std::initializer_list<TypeErrorMessageElement> list,
                                 const lexer::SourcePosition &err_pos)
{
    if (!IsTypeComparableTo(source, target)) {
        relation_->RaiseError(list, err_pos);
    }

    return true;
}

bool Checker::AreTypesComparable(Type *source, Type *target)
{
    return IsTypeComparableTo(source, target) || IsTypeComparableTo(target, source);
}

bool Checker::IsTypeEqualityComparableTo(Type *source, Type *target)
{
    return target->HasTypeFlag(TypeFlag::NULLABLE) || IsTypeComparableTo(source, target);
}

parser::Program *Checker::Program() const
{
    return program_;
}

void Checker::SetProgram(parser::Program *program)
{
    program_ = program;
}

binder::Binder *Checker::Binder() const
{
    return binder_;
}

}  // namespace panda::es2panda::checker
