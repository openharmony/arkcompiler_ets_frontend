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

#include "switchStatement.h"

#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/compiler/core/labelTarget.h"
#include "plugins/ecmascript/es2panda/compiler/core/switchBuilder.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/typeRelationContext.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/statements/switchCaseStatement.h"

namespace panda::es2panda::ir {
void SwitchStatement::Iterate(const NodeTraverser &cb) const
{
    cb(discriminant_);

    for (auto *it : cases_) {
        cb(it);
    }
}

void SwitchStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "SwitchStatement"}, {"discriminant", discriminant_}, {"cases", cases_}});
}

template <typename CodeGen>
void CompileImpl(const SwitchStatement *self, CodeGen *cg)
{
    compiler::LocalRegScope lrs(cg, self->Scope());
    compiler::SwitchBuilder builder(cg, self);
    compiler::VReg tag = cg->AllocReg();

    builder.CompileTagOfSwitch(tag);
    uint32_t default_index = 0;

    for (size_t i = 0; i < self->Cases().size(); i++) {
        const auto *clause = self->Cases()[i];

        if (clause->Test() == nullptr) {
            default_index = i;
            continue;
        }

        builder.JumpIfCase(tag, i);
    }

    if (default_index > 0) {
        builder.JumpToDefault(default_index);
    } else {
        builder.Break();
    }

    for (size_t i = 0; i < self->Cases().size(); i++) {
        builder.SetCaseTarget(i);
        builder.CompileCaseStatements(i);
    }
}

void SwitchStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    CompileImpl(this, pg);
}

void SwitchStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    CompileImpl(this, etsg);
}

checker::Type *SwitchStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, scope_);

    checker::Type *expr_type = discriminant_->Check(checker);
    bool expr_is_literal = checker::TSChecker::IsLiteralType(expr_type);

    for (auto *it : cases_) {
        if (it->Test() != nullptr) {
            checker::Type *case_type = it->Test()->Check(checker);
            bool case_is_literal = checker::TSChecker::IsLiteralType(case_type);
            checker::Type *compared_expr_type = expr_type;

            if (!case_is_literal || !expr_is_literal) {
                case_type = case_is_literal ? checker->GetBaseTypeOfLiteralType(case_type) : case_type;
                compared_expr_type = checker->GetBaseTypeOfLiteralType(expr_type);
            }

            if (!checker->IsTypeEqualityComparableTo(compared_expr_type, case_type) &&
                !checker->IsTypeComparableTo(case_type, compared_expr_type)) {
                checker->ThrowTypeError({"Type ", case_type, " is not comparable to type ", compared_expr_type},
                                        it->Test()->Start());
            }
        }

        for (auto *case_stmt : it->Consequent()) {
            case_stmt->Check(checker);
        }
    }

    return nullptr;
}

checker::Type *SwitchStatement::Check(checker::ETSChecker *const checker)
{
    checker::ScopeContext scope_ctx(checker, scope_);
    discriminant_->Check(checker);
    checker::SavedTypeRelationFlagsContext saved_type_relation_flag_ctx(checker->Relation(),
                                                                        checker::TypeRelationFlag::NONE);
    // TODO(user): check exhaustive Switch
    checker->CheckSwitchDiscriminant(discriminant_);
    auto *compared_expr_type = discriminant_->TsType();
    auto unboxed_disc_type = (Discriminant()->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::UNBOXING_FLAG) != 0U
                                 ? checker->ETSBuiltinTypeAsPrimitiveType(compared_expr_type)
                                 : compared_expr_type;
    bool valid_case_type;

    for (auto *it : cases_) {
        if (it->Test() != nullptr) {
            auto *case_type = it->Test()->Check(checker);
            valid_case_type = true;

            if (case_type->HasTypeFlag(checker::TypeFlag::CHAR)) {
                valid_case_type = compared_expr_type->HasTypeFlag(checker::TypeFlag::ETS_INTEGRAL);
            } else if (case_type->IsETSEnumType()) {
                valid_case_type = case_type->AsETSEnumType()->IsEnumLiteralExpression(it->Test()) &&
                                  compared_expr_type->HasTypeFlag(checker::TypeFlag::ETS_ENUM);
            } else {
                checker::AssignmentContext(
                    checker->Relation(), discriminant_, case_type, unboxed_disc_type, it->Test()->Start(),
                    {"Switch case type ", case_type, " is not comparable to discriminant type ", compared_expr_type},
                    (compared_expr_type->IsETSObjectType() ? checker::TypeRelationFlag::NO_WIDENING
                                                           : checker::TypeRelationFlag::NO_UNBOXING) |
                        checker::TypeRelationFlag::NO_BOXING);
            }

            if (!valid_case_type) {
                checker->ThrowTypeError(
                    {"Switch case type ", case_type, " is not comparable to discriminant type ", compared_expr_type},
                    it->Test()->Start());
            }
        }

        for (auto *case_stmt : it->Consequent()) {
            case_stmt->Check(checker);
        }
    }

    checker->CheckForSameSwitchCases(&cases_);

    return nullptr;
}
}  // namespace panda::es2panda::ir
