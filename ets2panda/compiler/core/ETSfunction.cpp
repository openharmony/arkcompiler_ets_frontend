/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ETSfunction.h"

#include "binder/binder.h"
#include "binder/ETSBinder.h"
#include "util/helpers.h"
#include "binder/scope.h"
#include "binder/variable.h"
#include "compiler/base/lreference.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/envScope.h"
#include "ir/base/spreadElement.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "checker/types/ets/types.h"

namespace panda::es2panda::compiler {
void ETSFunction::CallImplicitCtor(ETSGen *etsg)
{
    RegScope rs(etsg);
    auto *super_type = etsg->ContainingObjectType()->SuperType();

    if (super_type == nullptr) {
        etsg->CallThisStatic0(etsg->RootNode(), etsg->GetThisReg(), Signatures::BUILTIN_OBJECT_CTOR);

        return;
    }

    auto res = std::find_if(super_type->ConstructSignatures().cbegin(), super_type->ConstructSignatures().cend(),
                            [](const checker::Signature *sig) { return sig->Params().empty(); });

    if (res == super_type->ConstructSignatures().cend()) {
        return;
    }

    etsg->CallThisStatic0(etsg->RootNode(), etsg->GetThisReg(), (*res)->InternalName());
}

void ETSFunction::CompileSourceBlock(ETSGen *etsg, const ir::BlockStatement *block)
{
    auto *script_func = etsg->RootNode()->AsScriptFunction();
    if (script_func->IsEnum()) {
        // TODO(user): add enum methods
    } else if (script_func->IsStaticBlock()) {
        const auto *class_def = etsg->ContainingObjectType()->GetDeclNode()->AsClassDefinition();

        // Check if it is the Global class static constructor and the special '_$init$_" method exists
        bool compile_initializer = true;
        if (class_def->IsGlobal()) {
            for (const auto *prop : class_def->Body()) {
                if (prop->IsMethodDefinition() && prop->AsClassElement()->Key()->IsIdentifier()) {
                    if (prop->AsClassElement()->Key()->AsIdentifier()->Name() == compiler::Signatures::INIT_METHOD) {
                        compile_initializer = false;
                        break;
                    }
                }
            }
        }

        for (const auto *prop : class_def->Body()) {
            if (!prop->IsClassProperty() || !prop->IsStatic()) {
                continue;
            }

            // Don't compile variable initializers if they present in '_$init$_" method
            auto *const item = prop->AsClassProperty();
            auto *const value = item->Value();
            if (value != nullptr && (compile_initializer || item->IsConst() || value->IsArrowFunctionExpression())) {
                item->Compile(etsg);
            }
        }
    } else if (script_func->IsConstructor()) {
        if (script_func->IsImplicitSuperCallNeeded()) {
            CallImplicitCtor(etsg);
        }

        const auto *class_def = etsg->ContainingObjectType()->GetDeclNode()->AsClassDefinition();

        for (const auto *prop : class_def->Body()) {
            if (!prop->IsClassProperty() || prop->IsStatic()) {
                continue;
            }

            prop->AsClassProperty()->Compile(etsg);
        }
    }

    const auto &statements = block->Statements();

    if (statements.empty()) {
        etsg->SetFirstStmt(block);
        if (script_func->IsConstructor() || script_func->IsStaticBlock() || script_func->IsEntryPoint()) {
            ASSERT(etsg->ReturnType() != etsg->Checker()->GlobalBuiltinVoidType());
            etsg->EmitReturnVoid(block);

        } else {
            ASSERT(!etsg->ReturnType()->IsETSVoidType());
            etsg->LoadBuiltinVoid(block);
            etsg->ReturnAcc(block);
        }

        return;
    }

    etsg->SetFirstStmt(statements.front());

    etsg->CompileStatements(statements);

    if (!statements.back()->IsReturnStatement()) {
        if (script_func->IsConstructor() || script_func->IsStaticBlock() || script_func->IsEntryPoint()) {
            ASSERT(etsg->ReturnType() != etsg->Checker()->GlobalBuiltinVoidType());
            etsg->EmitReturnVoid(statements.back());
            return;
        }

        ASSERT(!etsg->ReturnType()->IsETSVoidType());

        if (script_func->Signature()->ReturnType() == etsg->Checker()->GlobalBuiltinVoidType()) {
            etsg->LoadBuiltinVoid(statements.back());
        } else {
            etsg->LoadDefaultValue(statements.back(), script_func->Signature()->ReturnType());
        }
        etsg->ReturnAcc(statements.back());
    }
}

void ETSFunction::CompileFunction(ETSGen *etsg)
{
    const auto *decl = etsg->RootNode()->AsScriptFunction();

    if (const ir::AstNode *body = decl->Body(); body->IsExpression()) {
        // TODO(user):
    } else {
        CompileSourceBlock(etsg, body->AsBlockStatement());
    }
}

void ETSFunction::Compile(ETSGen *etsg)
{
    FunctionRegScope lrs(etsg);
    auto *top_scope = etsg->TopScope();

    if (top_scope->IsFunctionScope()) {
        CompileFunction(etsg);
    } else {
        ASSERT(top_scope->IsGlobalScope());
        CompileSourceBlock(etsg, etsg->RootNode()->AsBlockStatement());
    }

    etsg->SortCatchTables();
}

}  // namespace panda::es2panda::compiler
