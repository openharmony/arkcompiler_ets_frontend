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

#include "function.h"

#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/compiler/base/lreference.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/classProperty.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/statements/blockStatement.h"

namespace panda::es2panda::compiler {
static void CompileSourceBlock(PandaGen *pg, const ir::BlockStatement *block)
{
    const auto &statements = block->Statements();
    if (statements.empty()) {
        pg->SetFirstStmt(block);
        pg->ImplicitReturn(block);
        return;
    }

    pg->SetFirstStmt(statements.front());

    for (const auto *stmt : statements) {
        stmt->Compile(pg);
    }

    switch (statements.back()->Type()) {
        case ir::AstNodeType::RETURN_STATEMENT: {
            return;
        }
        case ir::AstNodeType::VARIABLE_DECLARATION:
        case ir::AstNodeType::FUNCTION_DECLARATION:
        case ir::AstNodeType::STRUCT_DECLARATION:
        case ir::AstNodeType::CLASS_DECLARATION: {
            pg->ImplicitReturn(statements.back());
            break;
        }
        default: {
            if (pg->IsEval()) {
                pg->DirectReturn(statements.back());
            } else {
                pg->ImplicitReturn(statements.back());
            }
        }
    }
}

static void CompileFunctionParameterDeclaration(PandaGen *pg, const ir::ScriptFunction *func)
{
    ScopeContext scope_ctx(pg, func->Scope()->ParamScope());

    uint32_t index = 0;

    for (const auto *param : func->Params()) {
        auto ref = JSLReference::Create(pg, param, true);

        [[maybe_unused]] binder::Variable *param_var = ref.Variable();

        if (ref.Kind() == ReferenceKind::DESTRUCTURING) {
            util::StringView name = util::Helpers::ToStringView(pg->Allocator(), index);
            param_var = pg->Scope()->FindLocal(name, binder::ResolveBindingOptions::BINDINGS);
        }

        ASSERT(param_var && param_var->IsLocalVariable());

        VReg param_reg = VReg(binder::Binder::MANDATORY_PARAMS_NUMBER + VReg::PARAM_START + index++);
        ASSERT(param_var->LexicalBound() || param_var->AsLocalVariable()->Vreg() == param_reg);

        if (param->IsAssignmentPattern()) {
            RegScope rs(pg);
            pg->LoadAccumulator(func, param_reg);
            auto *non_default_label = pg->AllocLabel();

            if (ref.Kind() == ReferenceKind::DESTRUCTURING) {
                auto *load_param_label = pg->AllocLabel();

                pg->BranchIfNotUndefined(func, load_param_label);
                param->AsAssignmentPattern()->Right()->Compile(pg);
                pg->Branch(func, non_default_label);

                pg->SetLabel(func, load_param_label);
                pg->LoadAccumulator(func, param_reg);

                pg->SetLabel(func, non_default_label);
                ref.SetValue();
            } else {
                pg->BranchIfNotUndefined(func, non_default_label);

                param->AsAssignmentPattern()->Right()->Compile(pg);
                ref.SetValue();
                pg->SetLabel(func, non_default_label);
            }

            continue;
        }

        if (param->IsRestElement()) {
            pg->CopyRestArgs(param, func->Params().size() - 1);
        } else if (ref.Kind() == ReferenceKind::DESTRUCTURING) {
            pg->LoadAccumulator(func, param_reg);
        } else {
            continue;
        }
        ref.SetValue();
    }
}

void Function::LoadClassContexts(const ir::AstNode *node, PandaGen *pg, VReg ctor, const util::StringView &name)
{
    auto *class_def = util::Helpers::GetContainingClassDefinition(node);

    do {
        auto res = pg->Scope()->Find(class_def->PrivateId());
        ASSERT(res.variable);

        if (class_def->HasMatchingPrivateKey(name)) {
            pg->LoadLexicalVar(node, res.lex_level, res.variable->AsLocalVariable()->LexIdx());
            pg->StoreAccumulator(node, ctor);
            break;
        }

        class_def = util::Helpers::GetContainingClassDefinition(class_def->Parent());
    } while (class_def != nullptr);
}

void Function::CompileInstanceFields(PandaGen *pg, const ir::ScriptFunction *decl)
{
    const auto klass = util::Helpers::GetClassDefiniton(decl);
    const auto &elements = klass->Body();

    RegScope rs(pg);
    auto this_reg = pg->AllocReg();
    auto ctor = pg->AllocReg();
    pg->GetThis(decl);
    pg->StoreAccumulator(decl, this_reg);
    pg->GetFunctionObject(decl);
    pg->StoreAccumulator(decl, ctor);

    VReg computed_instance_fields_array {};
    uint32_t computed_instance_fields_index = 0;

    if (klass->HasPrivateMethod()) {
        pg->ClassPrivateMethodOrAccessorAdd(decl, ctor, this_reg);
    }

    if (klass->HasComputedInstanceField()) {
        computed_instance_fields_array = pg->AllocReg();
        pg->LoadClassComputedInstanceFields(klass, ctor);
        pg->StoreAccumulator(klass, computed_instance_fields_array);
    }

    for (auto const &element : elements) {
        if (!element->IsClassProperty()) {
            continue;
        }

        const auto *prop = element->AsClassProperty();

        if ((prop->IsStatic())) {
            continue;
        }

        if (prop->IsPrivateElement()) {
            if (prop->Value() == nullptr) {
                pg->LoadConst(element, Constant::JS_UNDEFINED);
            } else {
                RegScope scope_prop(pg);
                prop->Value()->Compile(pg);
            }

            pg->ClassPrivateFieldAdd(prop, ctor, this_reg, prop->Key()->AsIdentifier()->Name());
            continue;
        }

        RegScope key_scope(pg);

        Operand key;
        if (prop->IsComputed()) {
            VReg key_reg = pg->AllocReg();
            pg->LoadAccumulator(prop, computed_instance_fields_array);
            pg->LoadObjByIndex(prop, computed_instance_fields_index++);
            pg->StoreAccumulator(prop, key_reg);
            key = key_reg;
        } else {
            key = pg->ToOwnPropertyKey(prop->Key(), false);
        }

        if (prop->Value() == nullptr) {
            pg->LoadConst(element, Constant::JS_UNDEFINED);
        } else {
            RegScope scope_prop(pg);
            prop->Value()->Compile(pg);
        }

        pg->StoreOwnProperty(prop, this_reg, key);
    }
}

static void CompileFunction(PandaGen *pg)
{
    const auto *decl = pg->RootNode()->AsScriptFunction();

    if (decl->IsConstructor() && (util::Helpers::GetClassDefiniton(decl)->Super() == nullptr)) {
        Function::CompileInstanceFields(pg, decl);
    }

    auto *func_param_scope = pg->TopScope()->ParamScope();
    auto *name_var = func_param_scope->NameVar();

    if (name_var != nullptr) {
        RegScope rs(pg);
        pg->GetFunctionObject(pg->RootNode());
        pg->StoreAccToLexEnv(pg->RootNode(), func_param_scope->Find(name_var->Name()), true);
    }

    CompileFunctionParameterDeclaration(pg, decl);

    pg->FunctionEnter();
    const ir::AstNode *body = decl->Body();

    if (body->IsExpression()) {
        body->Compile(pg);
        pg->DirectReturn(decl);
    } else {
        CompileSourceBlock(pg, body->AsBlockStatement());
    }

    pg->FunctionExit();
}

void Function::Compile(PandaGen *pg)
{
    FunctionRegScope lrs(pg);
    auto *top_scope = pg->TopScope();

    if (pg->FunctionHasFinalizer()) {
        ASSERT(top_scope->IsFunctionScope());

        TryContext try_ctx(pg);
        pg->FunctionInit(try_ctx.GetCatchTable());

        CompileFunction(pg);
    } else {
        pg->FunctionInit(nullptr);

        if (top_scope->IsFunctionScope()) {
            CompileFunction(pg);
        } else {
            ASSERT(top_scope->IsGlobalScope() || top_scope->IsModuleScope());
            CompileSourceBlock(pg, pg->RootNode()->AsBlockStatement());
        }
    }

    pg->SortCatchTables();
}
}  // namespace panda::es2panda::compiler
