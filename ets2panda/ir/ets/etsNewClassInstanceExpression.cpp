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

#include "etsNewClassInstanceExpression.h"

#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsTypeReference.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsTypeReferencePart.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclarator.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsQualifiedName.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/types.h"

namespace panda::es2panda::ir {
void ETSNewClassInstanceExpression::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(type_reference_);

    for (auto *arg : arguments_) {
        cb(arg);
    }

    if (class_def_ != nullptr) {
        cb(class_def_);
    }
}

void ETSNewClassInstanceExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSNewClassInstanceExpression"},
                 {"typeReference", type_reference_},
                 {"arguments", arguments_},
                 {"classBody", AstDumper::Optional(class_def_)}});
}

void ETSNewClassInstanceExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ETSNewClassInstanceExpression::CreateDynamicObject(const ir::AstNode *node, compiler::ETSGen *etsg,
                                                        compiler::VReg &obj_reg, ir::Expression *name,
                                                        checker::Signature *signature,
                                                        const ArenaVector<ir::Expression *> &arguments)
{
    auto qname_reg = etsg->AllocReg();

    std::vector<util::StringView> parts;

    while (name->IsTSQualifiedName()) {
        auto *qname = name->AsTSQualifiedName();
        name = qname->Left();
        parts.push_back(qname->Right()->AsIdentifier()->Name());
    }

    auto *var = name->AsIdentifier()->Variable();
    auto *import = util::Helpers::ImportDeclarationForDynamicVar(var);
    if (import != nullptr) {
        ASSERT(import->Language().IsDynamic());
        etsg->LoadAccumulatorDynamicModule(node, import);
        auto *decl = var->Declaration()->Node();
        if (decl->IsImportSpecifier()) {
            parts.push_back(decl->AsImportSpecifier()->Imported()->Name());
        }
    } else {
        name->Compile(etsg);
    }

    etsg->StoreAccumulator(node, obj_reg);

    std::stringstream ss;
    std::for_each(parts.rbegin(), parts.rend(), [&ss](util::StringView sv) { ss << "." << sv; });

    etsg->LoadAccumulatorString(node, util::UString(ss.str(), etsg->Allocator()).View());
    etsg->StoreAccumulator(node, qname_reg);

    etsg->CallDynamic(node, obj_reg, qname_reg, signature, arguments);
}

void ETSNewClassInstanceExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    if (TsType()->IsETSDynamicType()) {
        auto obj_reg = etsg->AllocReg();
        auto *name = type_reference_->AsETSTypeReference()->Part()->Name();
        CreateDynamicObject(this, etsg, obj_reg, name, signature_, arguments_);
    } else {
        etsg->InitObject(this, signature_, arguments_);
    }

    if (GetBoxingUnboxingFlags() == ir::BoxingUnboxingFlags::NONE) {
        etsg->SetAccumulatorType(TsType());
    }
}

checker::Type *ETSNewClassInstanceExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSNewClassInstanceExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker::Type *callee_type = type_reference_->Check(checker);

    if (!callee_type->IsETSObjectType()) {
        checker->ThrowTypeError("This expression is not constructible.", Start());
    }

    auto *callee_obj = callee_type->AsETSObjectType();
    SetTsType(callee_obj);

    if (class_def_ != nullptr) {
        if (!callee_obj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT) && callee_obj->GetDeclNode()->IsFinal()) {
            checker->ThrowTypeError({"Class ", callee_obj->Name(), " cannot be both 'abstract' and 'final'."},
                                    callee_obj->GetDeclNode()->Start());
        }

        bool from_interface = callee_obj->HasObjectFlag(checker::ETSObjectFlags::INTERFACE);
        auto *class_type = checker->BuildAnonymousClassProperties(
            class_def_, from_interface ? checker->GlobalETSObjectType() : callee_obj);
        if (from_interface) {
            class_type->AddInterface(callee_obj);
            callee_obj = checker->GlobalETSObjectType();
        }
        class_def_->SetTsType(class_type);
        checker->CheckClassDefinition(class_def_);
        checker->CheckInnerClassMembers(class_type);
        SetTsType(class_type);
    } else if (callee_obj->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT)) {
        checker->ThrowTypeError({callee_obj->Name(), " is abstract therefore cannot be instantiated."}, Start());
    }

    if (callee_type->IsETSDynamicType()) {
        signature_ = checker->ResolveDynamicCallExpression(type_reference_, arguments_, true);
    } else {
        signature_ = checker->ResolveConstructExpression(callee_obj, arguments_, Start());

        checker->CheckObjectLiteralArguments(signature_, arguments_);
        checker->ValidateSignatureAccessibility(callee_obj, signature_, Start());

        ASSERT(signature_->Function() != nullptr);

        if (signature_->Function()->IsThrowing() || signature_->Function()->IsRethrowing()) {
            checker->CheckThrowingStatements(this);
        }
    }

    return TsType();
}
}  // namespace panda::es2panda::ir
