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

#include "returnStatement.h"

#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/typeRelationContext.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"

namespace panda::es2panda::ir {
void ReturnStatement::Iterate(const NodeTraverser &cb) const
{
    if (argument_ != nullptr) {
        cb(argument_);
    }
}

void ReturnStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ReturnStatement"}, {"argument", AstDumper::Nullable(argument_)}});
}

void ReturnStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    if (argument_ != nullptr) {
        argument_->Compile(pg);
    } else {
        pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
    }

    if (pg->CheckControlFlowChange()) {
        compiler::RegScope rs(pg);
        compiler::VReg res = pg->AllocReg();

        pg->StoreAccumulator(this, res);
        pg->ControlFlowChangeBreak();
        pg->LoadAccumulator(this, res);
    }

    if (argument_ != nullptr) {
        pg->ValidateClassDirectReturn(this);
        pg->DirectReturn(this);
    } else {
        pg->ImplicitReturn(this);
    }
}

void ReturnStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    if (argument_ == nullptr) {
        if (return_type_ == nullptr || return_type_->IsETSVoidType()) {
            if (etsg->ExtendWithFinalizer(parent_, this)) {
                return;
            }

            if (etsg->CheckControlFlowChange()) {
                etsg->ControlFlowChangeBreak();
            }
            etsg->EmitReturnVoid(this);
            return;
        }

        etsg->LoadBuiltinVoid(this);

    } else {
        auto ttctx = compiler::TargetTypeContext(etsg, etsg->ReturnType());

        if (!etsg->TryLoadConstantExpression(argument_)) {
            argument_->Compile(etsg);
        }
    }

    if (etsg->ExtendWithFinalizer(parent_, this)) {
        return;
    }

    if (etsg->CheckControlFlowChange()) {
        compiler::RegScope rs(etsg);
        compiler::VReg res = etsg->AllocReg();

        etsg->StoreAccumulator(this, res);
        etsg->ControlFlowChangeBreak();
        etsg->LoadAccumulator(this, res);
    }

    etsg->ApplyConversion(this, return_type_);
    etsg->ReturnAcc(this);
}

checker::Type *ReturnStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(this, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->Parent()->Parent()->IsMethodDefinition()) {
        const ir::MethodDefinition *containing_class_method = containing_func->Parent()->Parent()->AsMethodDefinition();
        if (containing_class_method->Kind() == ir::MethodDefinitionKind::SET) {
            checker->ThrowTypeError("Setters cannot return a value", Start());
        }
    }

    if (containing_func->ReturnTypeAnnotation() != nullptr) {
        checker::Type *return_type = checker->GlobalUndefinedType();
        checker::Type *func_return_type = containing_func->ReturnTypeAnnotation()->GetType(checker);

        if (argument_ != nullptr) {
            checker->ElaborateElementwise(func_return_type, argument_, Start());
            return_type = checker->CheckTypeCached(argument_);
        }

        checker->IsTypeAssignableTo(return_type, func_return_type,
                                    {"Type '", return_type, "' is not assignable to type '", func_return_type, "'."},
                                    Start());
    }

    return nullptr;
}

checker::Type *ReturnStatement::Check(checker::ETSChecker *checker)
{
    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(this, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->IsConstructor()) {
        if (argument_ != nullptr) {
            checker->ThrowTypeError("Return statement with expression isn't allowed in constructor.", Start());
        }
        return nullptr;
    }

    ASSERT(containing_func->ReturnTypeAnnotation() != nullptr ||
           // should be the implicit void return type
           containing_func->Signature()->ReturnType()->IsETSVoidType() ||
           containing_func->Signature()->ReturnType() == checker->GlobalBuiltinVoidType());

    return_type_ = containing_func->ReturnTypeAnnotation() != nullptr
                       ? checker->GetTypeFromTypeAnnotation(containing_func->ReturnTypeAnnotation())
                       : containing_func->Signature()->ReturnType();

    const auto name = containing_func->Scope()->InternalName().Mutf8();
    if (name.find(compiler::Signatures::ETS_MAIN_WITH_MANGLE_BEGIN) != std::string::npos) {
        if (return_type_ == checker->GlobalBuiltinVoidType()) {
            return_type_ = checker->GlobalVoidType();
        } else if (!return_type_->IsETSVoidType() && !return_type_->IsIntType()) {
            checker->ThrowTypeError("Bad return type, main enable only void or int type.", Start());
        }
    }

    if (argument_ == nullptr) {
        if (return_type_->IsETSVoidType() || return_type_ == checker->GlobalBuiltinVoidType()) {
            return nullptr;
        }

        checker->ThrowTypeError("Missing return value.", Start());
    }

    if (return_type_->IsETSVoidType()) {
        checker->ThrowTypeError("Unexpected return value, enclosing method return type is void.", argument_->Start());
    }

    if (argument_->IsObjectExpression()) {
        argument_->AsObjectExpression()->SetPreferredType(return_type_);
    }
    checker::Type *argument_type = argument_->Check(checker);

    checker::AssignmentContext(
        checker->Relation(), argument_, argument_type, return_type_, argument_->Start(),
        {"Return statements return type is not compatible with the containing functions return type"},
        checker::TypeRelationFlag::DIRECT_RETURN);

    return nullptr;
}
}  // namespace panda::es2panda::ir
