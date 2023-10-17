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
    ASSERT(ident_or_spread->IsIdentifier() || ident_or_spread->IsRestElement());
    if (ident_or_spread->IsRestElement()) {
        spread_ = ident_or_spread->AsRestElement();
        ASSERT(spread_->Argument()->IsIdentifier());
        ident_ = spread_->Argument()->AsIdentifier();
    } else {
        ident_ = ident_or_spread->AsIdentifier();
        spread_ = nullptr;
    }
}

const Identifier *ETSParameterExpression::Ident() const
{
    return ident_;
}

Identifier *ETSParameterExpression::Ident()
{
    return ident_;
}

const SpreadElement *ETSParameterExpression::Spread() const
{
    return spread_;
}

SpreadElement *ETSParameterExpression::Spread()
{
    return spread_;
}

const Expression *ETSParameterExpression::Initializer() const
{
    return initializer_;
}

Expression *ETSParameterExpression::Initializer()
{
    return initializer_;
}

binder::Variable *ETSParameterExpression::Variable() const
{
    return ident_->Variable();
}

void ETSParameterExpression::SetVariable(binder::Variable *const variable)
{
    ident_->SetVariable(variable);
}

void ETSParameterExpression::SetLexerSaved(util::StringView s)
{
    saved_lexer_ = s;
}

util::StringView ETSParameterExpression::LexerSaved() const
{
    return saved_lexer_;
}

bool ETSParameterExpression::IsDefault() const
{
    return initializer_ != nullptr;
}

void ETSParameterExpression::TransformChildren(const NodeTransformer &cb)
{
    ident_ = cb(ident_)->AsIdentifier();

    if (IsDefault()) {
        initializer_ = cb(initializer_)->AsExpression();
    }
}

void ETSParameterExpression::Iterate(const NodeTraverser &cb) const
{
    cb(ident_);

    if (IsDefault()) {
        cb(initializer_);
    }
}

void ETSParameterExpression::Dump(ir::AstDumper *const dumper) const
{
    if (spread_ == nullptr) {
        dumper->Add(
            {{"type", "ETSParameterExpression"}, {"name", ident_}, {"initializer", AstDumper::Optional(initializer_)}});
    } else {
        dumper->Add({{"type", "ETSParameterExpression"},
                     {"spread", spread_},
                     {"initializer", AstDumper::Optional(initializer_)}});
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
    if (ident_->TsType() != nullptr) {
        SetTsType(ident_->TsType());
        return TsType();
    }

    auto *const name_type =
        spread_ == nullptr ? ident_->TypeAnnotation()->GetType(checker) : spread_->TypeAnnotation()->GetType(checker);
    if (IsDefault()) {
        [[maybe_unused]] auto *const init_type = initializer_->Check(checker);
        // TODO(ttamas) : fix this aftet nullable fix
        // const checker::AssignmentContext ctx(checker->Relation(), initializer_, init_type, name_type,
        //                                      initializer_->Start(),
        //                                      {"Initializers type is not assignable to the target type"});
    }

    SetTsType(name_type);
    return TsType();
}

}  // namespace panda::es2panda::ir
