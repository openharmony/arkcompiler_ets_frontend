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

#include "etsParameterExpression.h"

#include "compiler/core/pandagen.h"
#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "ir/expressions/identifier.h"
#include "ir/base/spreadElement.h"

namespace panda::es2panda::ir {

ETSParameterExpression::ETSParameterExpression(AnnotatedExpression *const ident_or_spread,
                                               Expression *const initializer)
    : Expression(AstNodeType::ETS_PARAMETER_EXPRESSION), initializer_(initializer)
{
    ASSERT(ident_or_spread != nullptr);

    if (ident_or_spread->IsIdentifier()) {
        ident_ = ident_or_spread->AsIdentifier();
    } else if (ident_or_spread->IsRestElement()) {
        spread_ = ident_or_spread->AsRestElement();
        ASSERT(spread_->Argument()->IsIdentifier());
        ident_ = spread_->Argument()->AsIdentifier();
        initializer_ = nullptr;  // Just in case!
    } else {
        UNREACHABLE();
    }
}

const Identifier *ETSParameterExpression::Ident() const noexcept
{
    return ident_;
}

Identifier *ETSParameterExpression::Ident() noexcept
{
    return ident_;
}

const SpreadElement *ETSParameterExpression::RestParameter() const noexcept
{
    return spread_;
}

SpreadElement *ETSParameterExpression::RestParameter() noexcept
{
    return spread_;
}

const Expression *ETSParameterExpression::Initializer() const noexcept
{
    return initializer_;
}

Expression *ETSParameterExpression::Initializer() noexcept
{
    return initializer_;
}

binder::Variable *ETSParameterExpression::Variable() const noexcept
{
    return ident_->Variable();
}

TypeNode const *ETSParameterExpression::TypeAnnotation() const noexcept
{
    return !IsRestParameter() ? ident_->TypeAnnotation() : spread_->TypeAnnotation();
}

TypeNode *ETSParameterExpression::TypeAnnotation() noexcept
{
    return !IsRestParameter() ? ident_->TypeAnnotation() : spread_->TypeAnnotation();
}

void ETSParameterExpression::SetVariable(binder::Variable *const variable) noexcept
{
    ident_->SetVariable(variable);
}

void ETSParameterExpression::SetLexerSaved(util::StringView s) noexcept
{
    saved_lexer_ = s;
}

util::StringView ETSParameterExpression::LexerSaved() const noexcept
{
    return saved_lexer_;
}

void ETSParameterExpression::TransformChildren(const NodeTransformer &cb)
{
    if (IsRestParameter()) {
        spread_ = cb(spread_)->AsRestElement();
        ident_ = spread_->Argument()->AsIdentifier();
    } else {
        ident_ = cb(ident_)->AsIdentifier();
    }

    if (IsDefault()) {
        initializer_ = cb(initializer_)->AsExpression();
    }
}

void ETSParameterExpression::Iterate(const NodeTraverser &cb) const
{
    if (IsRestParameter()) {
        cb(spread_);
    } else {
        cb(ident_);
    }

    if (IsDefault()) {
        cb(initializer_);
    }
}

void ETSParameterExpression::Dump(ir::AstDumper *const dumper) const
{
    if (!IsRestParameter()) {
        dumper->Add(
            {{"type", "ETSParameterExpression"}, {"name", ident_}, {"initializer", AstDumper::Optional(initializer_)}});
    } else {
        dumper->Add({{"type", "ETSParameterExpression"}, {"rest parameter", spread_}});
    }
}

void ETSParameterExpression::Compile([[maybe_unused]] compiler::PandaGen *const pg) const
{
    UNREACHABLE();
}

void ETSParameterExpression::Compile([[maybe_unused]] compiler::ETSGen *const etsg) const
{
    ident_->Identifier::Compile(etsg);
}

checker::Type *ETSParameterExpression::Check([[maybe_unused]] checker::TSChecker *const checker)
{
    UNREACHABLE();
}

checker::Type *ETSParameterExpression::Check(checker::ETSChecker *const checker)
{
    if (TsType() == nullptr) {
        checker::Type *param_type;

        if (ident_->TsType() != nullptr) {
            param_type = ident_->TsType();
        } else {
            param_type = !IsRestParameter() ? ident_->Check(checker) : spread_->Check(checker);
            if (IsDefault()) {
                [[maybe_unused]] auto *const init_type = initializer_->Check(checker);
                // TODO(ttamas) : fix this aftet nullable fix
                // const checker::AssignmentContext ctx(checker->Relation(), initializer_, init_type, name_type,
                //                                      initializer_->Start(),
                //                                      {"Initializers type is not assignable to the target type"});
            }
        }

        SetTsType(param_type);
    }

    return TsType();
}

}  // namespace panda::es2panda::ir
