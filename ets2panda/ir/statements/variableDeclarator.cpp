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

#include "variableDeclarator.h"

#include "binder/variableFlags.h"
#include "compiler/base/lreference.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/astNode.h"
#include "ir/typeNode.h"
#include "ir/expression.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/identifier.h"

#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/ts/destructuringContext.h"

namespace panda::es2panda::ir {
void VariableDeclarator::TransformChildren(const NodeTransformer &cb)
{
    id_ = cb(id_)->AsExpression();

    if (init_ != nullptr) {
        init_ = cb(init_)->AsExpression();
    }
}

void VariableDeclarator::Iterate(const NodeTraverser &cb) const
{
    cb(id_);

    if (init_ != nullptr) {
        cb(init_);
    }
}

void VariableDeclarator::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "VariableDeclarator"}, {"id", id_}, {"init", AstDumper::Nullable(init_)}});
}

void VariableDeclarator::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    auto lref = compiler::JSLReference::Create(pg, id_, true);
    const ir::VariableDeclaration *decl = parent_->AsVariableDeclaration();

    if (init_ != nullptr) {
        init_->Compile(pg);
    } else {
        if (decl->Kind() == ir::VariableDeclaration::VariableDeclarationKind::VAR) {
            return;
        }
        if (decl->Kind() == ir::VariableDeclaration::VariableDeclarationKind::LET && !decl->Parent()->IsCatchClause()) {
            pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
        }
    }

    lref.SetValue();
}

void VariableDeclarator::Compile(compiler::ETSGen *etsg) const
{
    auto lref = compiler::ETSLReference::Create(etsg, id_, true);
    auto ttctx = compiler::TargetTypeContext(etsg, TsType());

    if (id_->AsIdentifier()->Variable()->HasFlag(binder::VariableFlags::BOXED)) {
        etsg->EmitLocalBoxCtor(id_);
        etsg->StoreAccumulator(this, lref.Variable()->AsLocalVariable()->Vreg());
    }

    if (init_ != nullptr) {
        if (!etsg->TryLoadConstantExpression(init_)) {
            init_->Compile(etsg);
            etsg->ApplyConversion(init_, nullptr);
        }
    } else {
        etsg->LoadDefaultValue(this, id_->AsIdentifier()->Variable()->TsType());
    }

    etsg->ApplyConversion(this, TsType());
    lref.SetValue();
}

static void CheckSimpleVariableDeclaration(checker::TSChecker *checker, ir::VariableDeclarator *declarator)
{
    binder::Variable *const binding_var = declarator->Id()->AsIdentifier()->Variable();
    checker::Type *previous_type = binding_var->TsType();
    auto *const type_annotation = declarator->Id()->AsIdentifier()->TypeAnnotation();
    auto *const initializer = declarator->Init();
    const bool is_const = declarator->Parent()->AsVariableDeclaration()->Kind() ==
                          ir::VariableDeclaration::VariableDeclarationKind::CONST;

    if (is_const) {
        checker->AddStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
    }

    if (type_annotation != nullptr) {
        type_annotation->Check(checker);
    }

    if (type_annotation != nullptr && initializer != nullptr) {
        checker::Type *const annotation_type = type_annotation->GetType(checker);
        checker->ElaborateElementwise(annotation_type, initializer, declarator->Id()->Start());
        binding_var->SetTsType(annotation_type);
    } else if (type_annotation != nullptr) {
        binding_var->SetTsType(type_annotation->GetType(checker));
    } else if (initializer != nullptr) {
        checker::Type *initializer_type = checker->CheckTypeCached(initializer);

        if (!is_const) {
            initializer_type = checker->GetBaseTypeOfLiteralType(initializer_type);
        }

        if (initializer_type->IsNullType()) {
            checker->ThrowTypeError(
                {"Cannot infer type for variable '", declarator->Id()->AsIdentifier()->Name(), "'."},
                declarator->Id()->Start());
        }

        binding_var->SetTsType(initializer_type);
    } else {
        checker->ThrowTypeError({"Variable ", declarator->Id()->AsIdentifier()->Name(), " implicitly has an any type."},
                                declarator->Id()->Start());
    }

    if (previous_type != nullptr) {
        checker->IsTypeIdenticalTo(binding_var->TsType(), previous_type,
                                   {"Subsequent variable declaration must have the same type. Variable '",
                                    binding_var->Name(), "' must be of type '", previous_type, "', but here has type '",
                                    binding_var->TsType(), "'."},
                                   declarator->Id()->Start());
    }

    checker->RemoveStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
}

checker::Type *VariableDeclarator::Check([[maybe_unused]] checker::TSChecker *checker)
{
    if (TsType() == CHECKED) {
        return nullptr;
    }

    if (id_->IsIdentifier()) {
        CheckSimpleVariableDeclaration(checker, this);
        SetTsType(CHECKED);
        return nullptr;
    }

    if (id_->IsArrayPattern()) {
        auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
        checker::ArrayDestructuringContext(checker, id_, false, id_->AsArrayPattern()->TypeAnnotation() == nullptr,
                                           id_->AsArrayPattern()->TypeAnnotation(), init_)
            .Start();

        SetTsType(CHECKED);
        return nullptr;
    }

    ASSERT(id_->IsObjectPattern());
    auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
    checker::ObjectDestructuringContext(checker, id_, false, id_->AsObjectPattern()->TypeAnnotation() == nullptr,
                                        id_->AsObjectPattern()->TypeAnnotation(), init_)
        .Start();

    SetTsType(CHECKED);
    return nullptr;
}

checker::Type *VariableDeclarator::Check(checker::ETSChecker *checker)
{
    ASSERT(id_->IsIdentifier());
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (id_->Parent()->Parent()->AsVariableDeclaration()->Kind() ==
        ir::VariableDeclaration::VariableDeclarationKind::CONST) {
        flags |= ir::ModifierFlags::CONST;
    }

    SetTsType(
        checker->CheckVariableDeclaration(id_->AsIdentifier(), id_->AsIdentifier()->TypeAnnotation(), init_, flags));
    return TsType();
}
}  // namespace panda::es2panda::ir
