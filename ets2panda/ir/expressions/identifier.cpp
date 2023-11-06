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

#include "identifier.h"

#include "binder/scope.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "ir/base/decorator.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
Identifier::Identifier([[maybe_unused]] Tag const tag, Identifier const &other, ArenaAllocator *const allocator)
    : AnnotatedExpression(static_cast<AnnotatedExpression const &>(other)), decorators_(allocator->Adapter())
{
    CloneTypeAnnotation(allocator);
    name_ = other.name_;
    flags_ = other.flags_;
    variable_ = other.variable_;

    for (auto *decorator : other.decorators_) {
        decorators_.emplace_back(decorator->Clone(allocator, this)->AsDecorator());
    }
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *Identifier::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<Identifier>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

void Identifier::TransformChildren(const NodeTransformer &cb)
{
    if (TypeAnnotation() != nullptr) {
        SetTsTypeAnnotation(static_cast<TypeNode *>(cb(TypeAnnotation())));
    }

    for (auto *&it : decorators_) {
        it = cb(it)->AsDecorator();
    }
}

void Identifier::Iterate(const NodeTraverser &cb) const
{
    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }

    for (auto *it : decorators_) {
        cb(it);
    }
}

ValidationInfo Identifier::ValidateExpression()
{
    if ((flags_ & IdentifierFlags::OPTIONAL) != 0U) {
        return {"Unexpected token '?'.", Start()};
    }

    if (TypeAnnotation() != nullptr) {
        return {"Unexpected token.", TypeAnnotation()->Start()};
    }

    ValidationInfo info;
    return info;
}

void Identifier::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", IsPrivateIdent() ? "PrivateIdentifier" : "Identifier"},
                 {"name", name_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())},
                 {"optional", AstDumper::Optional(IsOptional())},
                 {"decorators", decorators_}});
}

void Identifier::Compile(compiler::PandaGen *pg) const
{
    auto res = pg->Scope()->Find(name_);
    if (res.variable != nullptr) {
        pg->LoadVar(this, res);
        return;
    }

    if (pg->IsDirectEval()) {
        pg->LoadEvalVariable(this, name_);
        return;
    }

    if (name_.Is("NaN")) {
        pg->LoadConst(this, compiler::Constant::JS_NAN);
        return;
    }

    if (name_.Is("Infinity")) {
        pg->LoadConst(this, compiler::Constant::JS_INFINITY);
        return;
    }

    if (name_.Is("globalThis")) {
        pg->LoadConst(this, compiler::Constant::JS_GLOBAL);
        return;
    }

    if (name_.Is("undefined")) {
        pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
        return;
    }

    pg->TryLoadGlobalByName(this, name_);
}

void Identifier::Compile(compiler::ETSGen *etsg) const
{
    auto lambda = etsg->Binder()->LambdaObjects().find(this);
    if (lambda != etsg->Binder()->LambdaObjects().end()) {
        etsg->CreateLambdaObjectFromIdentReference(this, lambda->second.first);
        return;
    }

    auto ttctx = compiler::TargetTypeContext(etsg, TsType());

    ASSERT(variable_ != nullptr);
    if (!variable_->HasFlag(binder::VariableFlags::TYPE_ALIAS)) {
        etsg->LoadVar(this, variable_);
    } else {
        etsg->LoadVar(this, TsType()->Variable());
    }
}

checker::Type *Identifier::Check(checker::TSChecker *checker)
{
    if (Variable() == nullptr) {
        if (name_.Is("undefined")) {
            return checker->GlobalUndefinedType();
        }

        checker->ThrowTypeError({"Cannot find name ", name_}, Start());
    }

    const binder::Decl *decl = Variable()->Declaration();

    if (decl->IsTypeAliasDecl() || decl->IsInterfaceDecl()) {
        checker->ThrowTypeError({name_, " only refers to a type, but is being used as a value here."}, Start());
    }

    SetTsType(checker->GetTypeOfVariable(Variable()));
    return TsType();
}

checker::Type *Identifier::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    SetTsType(checker->ResolveIdentifier(this));
    if (TsType()->IsETSFunctionType()) {
        for (auto *sig : TsType()->AsETSFunctionType()->CallSignatures()) {
            if (sig->HasSignatureFlag(checker::SignatureFlags::NEED_RETURN_TYPE)) {
                sig->OwnerVar()->Declaration()->Node()->Check(checker);
            }
        }
    }
    return TsType();
}
}  // namespace panda::es2panda::ir
