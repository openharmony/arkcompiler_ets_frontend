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

#include "interfacePropertyDeclarations.h"

#include "checker/ETSchecker.h"
#include "checker/types/type.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/expressions/identifier.h"
#include "ir/opaqueTypeNode.h"
#include "ir/statements/blockStatement.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/base/classProperty.h"

namespace panda::es2panda::compiler {

std::string_view InterfacePropertyDeclarationsPhase::Name()
{
    return "interface-prop-decl";
}

static ir::MethodDefinition *GenerateGetterOrSetter(checker::ETSChecker *const checker, ir::ClassProperty *const field,
                                                    bool is_setter)
{
    auto class_scope = NearestScope(field);
    auto *param_scope = checker->Allocator()->New<varbinder::FunctionParamScope>(checker->Allocator(), class_scope);
    auto *function_scope = checker->Allocator()->New<varbinder::FunctionScope>(checker->Allocator(), param_scope);

    function_scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(function_scope);

    auto flags = ir::ModifierFlags::PUBLIC;
    flags |= ir::ModifierFlags::ABSTRACT;

    ArenaVector<ir::Expression *> params(checker->Allocator()->Adapter());

    if (is_setter) {
        auto param_ident = field->Key()->AsIdentifier()->Clone(checker->Allocator());
        param_ident->SetTsTypeAnnotation(field->TypeAnnotation()->Clone(checker->Allocator()));
        param_ident->TypeAnnotation()->SetParent(param_ident);

        auto param_expression = checker->AllocNode<ir::ETSParameterExpression>(param_ident, nullptr);
        param_expression->SetRange(param_ident->Range());
        const auto [_, __, param_var] = param_scope->AddParamDecl(checker->Allocator(), param_expression);
        (void)_;
        (void)__;

        param_ident->SetVariable(param_var);
        param_expression->SetVariable(param_var);

        params.push_back(param_expression);
    }

    auto signature = ir::FunctionSignature(nullptr, std::move(params), is_setter ? nullptr : field->TypeAnnotation());

    auto *func =
        is_setter
            ? checker->AllocNode<ir::ScriptFunction>(std::move(signature), nullptr, ir::ScriptFunctionFlags::SETTER,
                                                     flags, true, Language(Language::Id::ETS))
            : checker->AllocNode<ir::ScriptFunction>(std::move(signature), nullptr, ir::ScriptFunctionFlags::GETTER,
                                                     flags, true, Language(Language::Id::ETS));
    func->SetRange(field->Range());

    func->SetScope(function_scope);

    auto method_ident = field->Key()->AsIdentifier()->Clone(checker->Allocator());
    auto *decl = checker->Allocator()->New<varbinder::VarDecl>(field->Key()->AsIdentifier()->Name());
    auto var = function_scope->AddDecl(checker->Allocator(), decl, ScriptExtension::ETS);

    method_ident->SetVariable(var);

    auto *func_expr = checker->AllocNode<ir::FunctionExpression>(func);
    func_expr->SetRange(func->Range());
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);

    auto *method = checker->AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, method_ident, func_expr,
                                                            flags, checker->Allocator(), false);

    method->Id()->SetMutator();
    method->SetRange(field->Range());
    method->Function()->SetIdent(method->Id());
    method->Function()->AddModifier(method->Modifiers());
    param_scope->BindNode(func);
    function_scope->BindNode(func);

    return method;
}

static ir::Expression *UpdateInterfacePropertys(checker::ETSChecker *const checker,
                                                ir::TSInterfaceBody *const interface)
{
    if (interface->Body().empty()) {
        return interface;
    }

    auto property_list = interface->Body();
    ArenaVector<ir::AstNode *> new_property_list(checker->Allocator()->Adapter());

    auto scope = NearestScope(interface);
    ASSERT(scope->IsClassScope());

    for (const auto &prop : property_list) {
        if (!prop->IsClassProperty()) {
            new_property_list.emplace_back(prop);
            continue;
        }
        auto getter = GenerateGetterOrSetter(checker, prop->AsClassProperty(), false);
        new_property_list.emplace_back(getter);

        auto method_scope = scope->AsClassScope()->InstanceMethodScope();
        auto name = getter->Key()->AsIdentifier()->Name();

        auto *decl = checker->Allocator()->New<varbinder::FunctionDecl>(checker->Allocator(), name, getter);
        auto var = method_scope->AddDecl(checker->Allocator(), decl, ScriptExtension::ETS);

        if (var == nullptr) {
            auto prev_decl = method_scope->FindDecl(name);
            ASSERT(prev_decl->IsFunctionDecl());
            prev_decl->Node()->AsMethodDefinition()->AddOverload(getter);

            if (!prop->AsClassProperty()->IsReadonly()) {
                auto setter = GenerateGetterOrSetter(checker, prop->AsClassProperty(), true);
                new_property_list.emplace_back(setter);
                prev_decl->Node()->AsMethodDefinition()->AddOverload(setter);
            }

            getter->Function()->Id()->SetVariable(
                method_scope->FindLocal(name, varbinder::ResolveBindingOptions::BINDINGS));
            continue;
        }

        if (!prop->AsClassProperty()->IsReadonly()) {
            auto setter = GenerateGetterOrSetter(checker, prop->AsClassProperty(), true);
            new_property_list.emplace_back(setter);
            getter->AddOverload(setter);
        }
        getter->Function()->Id()->SetVariable(var);
        scope->AsClassScope()->InstanceFieldScope()->EraseBinding(name);
    }

    auto new_interface = checker->AllocNode<ir::TSInterfaceBody>(std::move(new_property_list));
    new_interface->SetRange(interface->Range());
    new_interface->SetParent(interface->Parent());

    return new_interface;
}

bool InterfacePropertyDeclarationsPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const ext_prog : ext_programs) {
            Perform(ctx, ext_prog);
        }
    }

    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively([checker](ir::AstNode *const ast) -> ir::AstNode * {
        return ast->IsTSInterfaceBody() ? UpdateInterfacePropertys(checker, ast->AsTSInterfaceBody()) : ast;
    });

    return true;
}

}  // namespace panda::es2panda::compiler
