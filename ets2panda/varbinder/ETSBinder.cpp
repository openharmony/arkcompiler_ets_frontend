/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "ETSBinder.h"

#include "ir/expressions/identifier.h"
#include "ir/expressions/thisExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classElement.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/statements/returnStatement.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsScript.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/module/importDeclaration.h"
#include "ir/module/importSpecifier.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "parser/program/program.h"
#include "util/helpers.h"
#include "util/ustring.h"
#include "checker/types/type.h"
#include "checker/types/ets/types.h"

namespace panda::es2panda::varbinder {

void ETSBinder::IdentifierAnalysis()
{
    ASSERT(Program()->Ast());
    ASSERT(GetScope() == TopScope());
    ASSERT(VarScope() == TopScope());

    record_table_->SetProgram(Program());
    global_record_table_.SetClassDefinition(Program()->GlobalClass());
    external_record_table_.insert({Program(), &global_record_table_});

    BuildProgram();

    ASSERT(global_record_table_.ClassDefinition() == Program()->GlobalClass());
}

void ETSBinder::LookupTypeArgumentReferences(ir::ETSTypeReference *type_ref)
{
    auto *iter = type_ref->Part();

    while (iter != nullptr) {
        if (iter->TypeParams() == nullptr) {
            iter = iter->Previous();
            continue;
        }

        ResolveReferences(iter->TypeParams());
        iter = iter->Previous();
    }
}

void ETSBinder::LookupTypeReference(ir::Identifier *ident, bool allow_dynamic_namespaces)
{
    const auto &name = ident->Name();
    auto *iter = GetScope();

    while (iter != nullptr) {
        auto res = iter->Find(name, ResolveBindingOptions::DECLARATION | ResolveBindingOptions::TYPE_ALIASES);
        if (res.variable == nullptr) {
            break;
        }

        if (IsDynamicModuleVariable(res.variable)) {
            ident->SetVariable(res.variable);
            return;
        }

        if (allow_dynamic_namespaces && IsDynamicNamespaceVariable(res.variable)) {
            ident->SetVariable(res.variable);
            return;
        }

        switch (res.variable->Declaration()->Node()->Type()) {
            case ir::AstNodeType::CLASS_DECLARATION:
            case ir::AstNodeType::CLASS_DEFINITION:
            case ir::AstNodeType::STRUCT_DECLARATION:
            case ir::AstNodeType::TS_ENUM_DECLARATION:
            case ir::AstNodeType::TS_INTERFACE_DECLARATION:
            case ir::AstNodeType::TS_TYPE_PARAMETER:
            case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
            case ir::AstNodeType::IMPORT_NAMESPACE_SPECIFIER: {
                ident->SetVariable(res.variable);
                return;
            }
            default: {
                iter = iter->Parent();
            }
        }
    }

    ThrowUnresolvableType(ident->Start(), name);
}

void ETSBinder::ResolveReferencesForScope(ir::AstNode const *const parent, Scope *const scope)
{
    parent->Iterate([this, scope](auto *node) { ResolveReferenceForScope(node, scope); });
}

void ETSBinder::ResolveReferenceForScope(ir::AstNode *const node, Scope *const scope)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            auto *ident = node->AsIdentifier();
            if (auto const res = scope->Find(ident->Name(), ResolveBindingOptions::ALL); res.variable != nullptr) {
                ident->SetVariable(res.variable);
            }
            break;
        }
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            auto scope_ctx = LexicalScope<Scope>::Enter(this, scope);
            BuildVarDeclarator(node->AsVariableDeclarator());
            break;
        }
        /* Maybe will be used
        case ir::AstNodeType::BLOCK_STATEMENT: {
            auto scope_ctx = LexicalScope<Scope>::Enter(this, node->AsBlockStatement()->Scope());
            ResolveReferences(node);
            break;
        }
        */
        default: {
            ResolveReferencesForScope(node, scope);
            break;
        }
    }
}

void ETSBinder::LookupIdentReference(ir::Identifier *ident)
{
    const auto &name = ident->Name();
    auto res = GetScope()->Find(name, ResolveBindingOptions::ALL);
    if (res.level != 0) {
        ASSERT(res.variable != nullptr);

        auto *outer_function = GetScope()->EnclosingVariableScope()->Node();

        if ((!outer_function->IsScriptFunction() || !outer_function->AsScriptFunction()->IsArrow()) &&
            !res.variable->IsGlobalVariable() && res.level > 1) {
            ThrowInvalidCapture(ident->Start(), name);
        }
    }

    if (res.variable == nullptr) {
        return;
    }

    if (ident->IsReference() && res.variable->Declaration()->IsLetOrConstDecl() &&
        !res.variable->HasFlag(VariableFlags::INITIALIZED)) {
        ThrowTDZ(ident->Start(), name);
    }
}

void ETSBinder::BuildClassProperty(const ir::ClassProperty *prop)
{
    ResolveReferences(prop);
}

void ETSBinder::InitializeInterfaceIdent(ir::TSInterfaceDeclaration *decl)
{
    auto res = GetScope()->Find(decl->Id()->Name());

    ASSERT(res.variable && res.variable->Declaration()->IsInterfaceDecl());
    res.variable->AddFlag(VariableFlags::INITIALIZED);
    decl->Id()->SetVariable(res.variable);
}

void ETSBinder::ResolveEnumDeclaration(ir::TSEnumDeclaration *enum_decl)
{
    auto enum_scope_ctx = LexicalScope<LocalScope>::Enter(this, enum_decl->Scope());

    for (auto *member : enum_decl->Members()) {
        ResolveReference(member);
    }
}

void ETSBinder::ResolveInterfaceDeclaration(ir::TSInterfaceDeclaration *decl)
{
    auto bound_ctx = BoundContext(record_table_, decl);

    for (auto *extend : decl->Extends()) {
        ResolveReference(extend);
    }

    auto scope_ctx = LexicalScope<ClassScope>::Enter(this, decl->Scope()->AsClassScope());

    for (auto *stmt : decl->Body()->Body()) {
        if (!stmt->IsClassProperty()) {
            continue;
        }

        ResolveReference(stmt);

        auto field_var =
            ResolvePropertyReference(stmt->AsClassProperty(), decl->Scope()->AsClassScope())
                ->FindLocal(stmt->AsClassProperty()->Id()->Name(), varbinder::ResolveBindingOptions::BINDINGS);
        field_var->AddFlag(VariableFlags::INITIALIZED);
    }

    for (auto *stmt : decl->Body()->Body()) {
        if (stmt->IsClassProperty()) {
            continue;
        }
        ResolveReference(stmt);
    }
}

void ETSBinder::BuildInterfaceDeclaration(ir::TSInterfaceDeclaration *decl)
{
    if (decl->TypeParams() != nullptr) {
        auto type_param_scope_ctx = LexicalScope<LocalScope>::Enter(this, decl->TypeParams()->Scope());
        ResolveReferences(decl->TypeParams());
        ResolveInterfaceDeclaration(decl);
        return;
    }

    ResolveInterfaceDeclaration(decl);
}

void ETSBinder::BuildMethodDefinition(ir::MethodDefinition *method_def)
{
    if (method_def->Function()->TypeParams() != nullptr) {
        auto scope_ctx = LexicalScope<LocalScope>::Enter(this, method_def->Function()->TypeParams()->Scope());
        ResolveReferences(method_def->Function()->TypeParams());
        ResolveMethodDefinition(method_def);
        return;
    }

    ResolveMethodDefinition(method_def);
}

void ETSBinder::ResolveMethodDefinition(ir::MethodDefinition *method_def)
{
    auto *func = method_def->Function();
    ResolveReferences(method_def);

    if (method_def->IsStatic() || func->IsStaticBlock()) {
        return;
    }

    auto param_scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, func->Scope()->ParamScope());

    auto params = func->Scope()->ParamScope()->Params();
    if (!params.empty() && params.front()->Name() == MANDATORY_PARAM_THIS) {
        return;  // Implicit this parameter is already inserted by ResolveReferences(), don't insert it twice.
    }

    auto *this_param = AddMandatoryParam(MANDATORY_PARAM_THIS);
    this_param->Declaration()->BindNode(this_param_);
}

void ETSBinder::BuildMemberExpression(ir::MemberExpression *member_expr)
{
    ResolveReference(member_expr->Object());

    if (member_expr->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS) {
        ResolveReference(member_expr->Property());
    }
}

void ETSBinder::BuildClassDefinition(ir::ClassDefinition *class_def)
{
    auto bound_ctx = BoundContext(record_table_, class_def);

    if (class_def->TypeParams() != nullptr) {
        auto scope_ctx = LexicalScope<LocalScope>::Enter(this, class_def->TypeParams()->Scope());
        ResolveReferences(class_def->TypeParams());
        BuildClassDefinitionImpl(class_def);
        return;
    }

    BuildClassDefinitionImpl(class_def);
}

LocalScope *ETSBinder::ResolvePropertyReference(ir::ClassProperty *prop, ClassScope *scope)
{
    ResolveReferences(prop);

    if (prop->IsStatic()) {
        return scope->StaticFieldScope();
    }

    return scope->InstanceFieldScope();
}

void ETSBinder::BuildClassDefinitionImpl(ir::ClassDefinition *class_def)
{
    auto class_ctx = LexicalScope<ClassScope>::Enter(this, class_def->Scope()->AsClassScope());

    if (class_def->Super() != nullptr) {
        ResolveReference(class_def->Super());
    }

    for (auto *impl : class_def->Implements()) {
        ResolveReference(impl);
    }

    for (auto *stmt : class_def->Body()) {
        if (!stmt->IsClassProperty()) {
            continue;
        }

        auto field_scope = ResolvePropertyReference(stmt->AsClassProperty(), class_def->Scope()->AsClassScope());
        auto field_name = stmt->AsClassProperty()->Id()->Name();
        auto field_var = field_scope->FindLocal(field_name, varbinder::ResolveBindingOptions::BINDINGS);
        field_var->AddFlag(VariableFlags::INITIALIZED);
        if (field_var->Declaration()->IsConstDecl() && stmt->AsClassProperty()->Value() == nullptr) {
            field_var->AddFlag(VariableFlags::EXPLICIT_INIT_REQUIRED);
        }
    }

    for (auto *stmt : class_def->Body()) {
        if (stmt->IsClassProperty()) {
            continue;
        }
        ResolveReference(stmt);
    }
}

void ETSBinder::AddLambdaFunctionThisParam(ir::ScriptFunction *func)
{
    auto param_scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, func->Scope()->ParamScope());
    auto *this_param = AddMandatoryParam(MANDATORY_PARAM_THIS);
    this_param->Declaration()->BindNode(this_param_);
    if (!func->IsAsyncFunc()) {
        Functions().push_back(func->Scope());
    }
}

void ETSBinder::AddInvokeFunctionThisParam(ir::ScriptFunction *func)
{
    auto param_scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, func->Scope()->ParamScope());
    auto *this_param = AddMandatoryParam(MANDATORY_PARAM_THIS);
    this_param->Declaration()->BindNode(this_param_);
}

void ETSBinder::BuildProxyMethod(ir::ScriptFunction *func, const util::StringView &containing_class_name,
                                 bool is_static)
{
    ASSERT(!containing_class_name.Empty());
    func->Scope()->BindName(containing_class_name);

    if (!is_static) {
        auto param_scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, func->Scope()->ParamScope());
        auto *this_param = AddMandatoryParam(MANDATORY_PARAM_THIS);
        this_param->Declaration()->BindNode(this_param_);
    }

    if (!func->IsAsyncFunc()) {
        Functions().push_back(func->Scope());
    }
}

void ETSBinder::BuildLambdaObject(ir::AstNode *ref_node, ir::ClassDefinition *lambda_object,
                                  checker::Signature *signature)
{
    auto bound_ctx = BoundContext(GetGlobalRecordTable(), lambda_object);
    const auto &lambda_body = lambda_object->Body();

    AddLambdaFunctionThisParam(lambda_body[lambda_body.size() - 2U]->AsMethodDefinition()->Function());
    AddLambdaFunctionThisParam(lambda_body[lambda_body.size() - 1]->AsMethodDefinition()->Function());

    LambdaObjects().insert({ref_node, {lambda_object, signature}});
}

void ETSBinder::BuildFunctionType(ir::ETSFunctionType *func_type)
{
    auto bound_ctx = BoundContext(GetGlobalRecordTable(), func_type->FunctionalInterface());

    auto *invoke_func = func_type->FunctionalInterface()->Body()->Body()[0]->AsMethodDefinition()->Function();
    auto *func_scope = invoke_func->Scope();
    func_scope->BindName(record_table_->RecordName());
    AddInvokeFunctionThisParam(invoke_func);

    GetGlobalRecordTable()->Signatures().push_back(func_scope);
}

void ETSBinder::AddDynamicSpecifiersToTopBindings(ir::AstNode *const specifier,
                                                  const ir::ETSImportDeclaration *const import)
{
    const auto name = [specifier]() {
        if (specifier->IsImportNamespaceSpecifier()) {
            return specifier->AsImportNamespaceSpecifier()->Local()->Name();
        }

        return specifier->AsImportSpecifier()->Local()->Name();
    }();

    auto *const decl = Allocator()->New<varbinder::LetDecl>(name, specifier);
    auto *const var = Allocator()->New<varbinder::LocalVariable>(decl, varbinder::VariableFlags::STATIC);
    var->AddFlag(VariableFlags::INITIALIZED);

    dynamic_import_vars_.emplace(var, DynamicImportData {import, specifier, var});

    TopScope()->InsertDynamicBinding(name, var);
}

bool ETSBinder::AddImportNamespaceSpecifiersToTopBindings(ir::AstNode *const specifier,
                                                          const varbinder::Scope::VariableMap &global_bindings,
                                                          const parser::Program *const import_program,
                                                          const varbinder::GlobalScope *const import_global_scope,
                                                          const ir::ETSImportDeclaration *const import)
{
    if (!specifier->IsImportNamespaceSpecifier()) {
        return false;
    }
    const auto *const namespace_specifier = specifier->AsImportNamespaceSpecifier();
    auto insert_foreign_binding = [this, specifier, import](const util::StringView &name, Variable *var) {
        if (import->Language().IsDynamic()) {
            dynamic_import_vars_.emplace(var, DynamicImportData {import, specifier, var});
        }

        TopScope()->InsertForeignBinding(name, var);
    };

    if (namespace_specifier->Local()->Name().Empty()) {
        for (const auto [bindingName, var] : global_bindings) {
            if (bindingName.Is(compiler::Signatures::ETS_GLOBAL)) {
                const auto *const class_def = var->Declaration()->Node()->AsClassDeclaration()->Definition();
                ImportGlobalProperties(class_def);
                continue;
            }

            if (!import_global_scope->IsForeignBinding(bindingName) &&
                !var->Declaration()->Node()->IsDefaultExported()) {
                insert_foreign_binding(bindingName, var);
            }
        }

        for (const auto [bindingName, var] : import_program->GlobalClassScope()->StaticMethodScope()->Bindings()) {
            if (!var->Declaration()->Node()->IsDefaultExported()) {
                insert_foreign_binding(bindingName, var);
            }
        }

        for (const auto [bindingName, var] : import_program->GlobalClassScope()->StaticFieldScope()->Bindings()) {
            if (!var->Declaration()->Node()->IsDefaultExported()) {
                insert_foreign_binding(bindingName, var);
            }
        }
    }

    std::unordered_set<std::string> exported_names;
    for (auto item : ReExportImports()) {
        if (auto source = import->ResolvedSource()->Str().Mutf8(),
            program = item->GetProgramPath().Mutf8().substr(0, item->GetProgramPath().Mutf8().find_last_of('.'));
            source == program || (source + "/index") == program) {
            ir::StringLiteral dir_name(util::UString(util::StringView(item->GetProgramPath().Mutf8().substr(
                                                         0, item->GetProgramPath().Mutf8().find_last_of('/'))),
                                                     Allocator())
                                           .View());
            dir_name.SetStart(item->GetETSImportDeclarations()->Source()->Start());

            for (auto it : item->GetETSImportDeclarations()->Specifiers()) {
                if (it->IsImportNamespaceSpecifier() &&
                    !specifier->AsImportNamespaceSpecifier()->Local()->Name().Empty()) {
                    std::cerr << "Warning: import with alias cannot be used with re-export\n";
                    continue;
                }

                AddSpecifiersToTopBindings(it, item->GetETSImportDeclarations(),
                                           dir_name.Str().Is(".") ? item->GetETSImportDeclarations()->Source()
                                                                  : &dir_name);
                if (it->IsImportSpecifier() &&
                    !exported_names.insert(it->AsImportSpecifier()->Local()->Name().Mutf8()).second) {
                    ThrowError(import->Start(), "Ambiguous import \"" +
                                                    it->AsImportSpecifier()->Local()->Name().Mutf8() +
                                                    "\" has multiple matching exports");
                }
            }
        }
    }

    return true;
}

Variable *ETSBinder::FindImportSpecifiersVariable(const util::StringView &imported,
                                                  const varbinder::Scope::VariableMap &global_bindings,
                                                  const ArenaVector<parser::Program *> &record_res)
{
    auto found_var = global_bindings.find(imported);
    if (found_var == global_bindings.end()) {
        const auto &static_method_bindings = record_res.front()->GlobalClassScope()->StaticMethodScope()->Bindings();
        found_var = static_method_bindings.find(imported);
        if (found_var != static_method_bindings.end()) {
            return found_var->second;
        }
        bool found = false;
        for (auto res : record_res) {
            const auto &static_field_bindings = res->GlobalClassScope()->StaticFieldScope()->Bindings();
            found_var = static_field_bindings.find(imported);
            if (found_var != static_field_bindings.end()) {
                found = true;
                found_var->second->AsLocalVariable()->AddFlag(VariableFlags::INITIALIZED);
                break;
            }
        }
        if (!found) {
            return nullptr;
        }
    }

    return found_var->second;
}

bool ETSBinder::AddImportSpecifiersToTopBindings(ir::AstNode *const specifier,
                                                 const varbinder::Scope::VariableMap &global_bindings,
                                                 const ir::ETSImportDeclaration *const import,
                                                 const ArenaVector<parser::Program *> &record_res,
                                                 std::vector<ir::ETSImportDeclaration *> viewed_re_export)
{
    if (!specifier->IsImportSpecifier()) {
        return false;
    }
    const ir::StringLiteral *const import_path = import->Source();
    auto insert_foreign_binding = [this, specifier, import](const util::StringView &name, Variable *var) {
        if (import->Language().IsDynamic()) {
            dynamic_import_vars_.emplace(var, DynamicImportData {import, specifier, var});
        }

        TopScope()->InsertForeignBinding(name, var);
    };

    const auto *const import_specifier = specifier->AsImportSpecifier();

    if (!import_specifier->Imported()->IsIdentifier()) {
        return true;
    }

    const auto &imported = import_specifier->Imported()->AsIdentifier()->Name();

    auto *const var = FindImportSpecifiersVariable(imported, global_bindings, record_res);

    const auto &local_name = [this, import_specifier, &imported, &import_path]() {
        if (import_specifier->Local() != nullptr) {
            auto fnc = [&import_path, &imported](const auto &saved_specifier) {
                return import_path->Str() != saved_specifier.first && imported == saved_specifier.second;
            };
            if (!std::any_of(import_specifiers_.begin(), import_specifiers_.end(), fnc)) {
                TopScope()->EraseBinding(imported);
            }

            import_specifiers_.push_back(std::make_pair(import_path->Str(), imported));

            return import_specifier->Local()->Name();
        }

        return imported;
    }();

    if (var == nullptr) {
        for (auto item : ReExportImports()) {
            if (auto source = import->ResolvedSource()->Str().Mutf8(),
                program = item->GetProgramPath().Mutf8().substr(0, item->GetProgramPath().Mutf8().find_last_of('.'));
                source == program || (source + "/index") == program) {
                ir::StringLiteral dir_name(util::UString(util::StringView(item->GetProgramPath().Mutf8().substr(
                                                             0, item->GetProgramPath().Mutf8().find_last_of('/'))),
                                                         Allocator())
                                               .View());
                dir_name.SetStart(item->GetETSImportDeclarations()->Source()->Start());

                viewed_re_export.push_back(item->GetETSImportDeclarations());
                AddSpecifiersToTopBindings(
                    specifier, item->GetETSImportDeclarations(),
                    dir_name.Str().Is(".") ? item->GetETSImportDeclarations()->Source() : &dir_name, viewed_re_export);
                return true;
            }
        }
        ThrowError(import_path->Start(), "Cannot find imported element " + imported.Mutf8());
    }

    if (var->Declaration()->Node()->IsDefaultExported()) {
        ThrowError(import_path->Start(), "Use the default import syntax to import a default exported element");
    }

    insert_foreign_binding(local_name, var);
    return true;
}

varbinder::Variable *ETSBinder::FindStaticBinding(const ArenaVector<parser::Program *> &record_res,
                                                  const ir::StringLiteral *const import_path)
{
    auto predicate_func = [](const auto &item) { return item.second->Declaration()->Node()->IsDefaultExported(); };
    const auto &static_method_bindings = record_res.front()->GlobalClassScope()->StaticMethodScope()->Bindings();
    auto result = std::find_if(static_method_bindings.begin(), static_method_bindings.end(), predicate_func);
    if (result == static_method_bindings.end()) {
        const auto &static_field_bindings = record_res.front()->GlobalClassScope()->StaticFieldScope()->Bindings();
        result = std::find_if(static_field_bindings.begin(), static_field_bindings.end(), predicate_func);
        if (result == static_field_bindings.end()) {
            ThrowError(import_path->Start(), "Cannot find default imported element in the target");
        }
    }
    return result->second;
}

ArenaVector<parser::Program *> ETSBinder::GetExternalProgram(const util::StringView &source_name,
                                                             const ir::StringLiteral *import_path)
{
    const auto &ext_records = global_record_table_.Program()->ExternalSources();
    auto record_res = [this, ext_records, source_name]() {
        auto res = ext_records.find(source_name);

        if (res != ext_records.end()) {
            return res;
        }

        if (res = ext_records.find({source_name.Mutf8() + "/index"}); res != ext_records.end()) {
            return res;
        }

        res = ext_records.find(GetResolvedImportPath(source_name));

        if (res == ext_records.end()) {
            res = ext_records.find(GetResolvedImportPath({source_name.Mutf8() + "/index"}));
        }

        return res;
    }();
    if (record_res == ext_records.end()) {
        ThrowError(import_path->Start(), "Cannot find import: " + std::string(source_name));
    }

    ASSERT(!record_res->second.empty());

    return record_res->second;
}

void ETSBinder::AddSpecifiersToTopBindings(ir::AstNode *const specifier, const ir::ETSImportDeclaration *const import,
                                           ir::StringLiteral *path,
                                           std::vector<ir::ETSImportDeclaration *> viewed_re_export)
{
    const ir::StringLiteral *const import_path = path;

    if (import->IsPureDynamic()) {
        AddDynamicSpecifiersToTopBindings(specifier, import);
        return;
    }

    const util::StringView source_name = [import, import_path, this, &path]() {
        if (import->Module() == nullptr) {
            return import_path->Str();
        }
        char path_delimiter = panda::os::file::File::GetPathDelim().at(0);
        auto str_import_path = import_path->Str().Mutf8();
        if (str_import_path.find(path_delimiter) == (str_import_path.size() - 1)) {
            return util::UString(str_import_path + import->Module()->Str().Mutf8(), Allocator()).View();
        }

        std::string import_file_path;
        if (!import->Source()->Str().Is(path->Str().Mutf8()) && !import->Source()->Str().Empty() &&
            import->Source()->Str().Mutf8().substr(0, 1) == ".") {
            import_file_path =
                import->Source()->Str().Mutf8().substr(import->Source()->Str().Mutf8().find_first_not_of('.'));
            if (import_file_path.size() == 1) {
                import_file_path = "";
            }
        }

        return util::UString(str_import_path + import_file_path + path_delimiter + import->Module()->Str().Mutf8(),
                             Allocator())
            .View();
    }();

    auto record = GetExternalProgram(source_name, import_path);
    const auto *const import_program = record.front();
    const auto *const import_global_scope = import_program->GlobalScope();
    const auto &global_bindings = import_global_scope->Bindings();

    auto insert_foreign_binding = [this, specifier, import](const util::StringView &name, Variable *var) {
        if (import->Language().IsDynamic()) {
            dynamic_import_vars_.emplace(var, DynamicImportData {import, specifier, var});
        }

        TopScope()->InsertForeignBinding(name, var);
    };

    if (AddImportNamespaceSpecifiersToTopBindings(specifier, global_bindings, import_program, import_global_scope,
                                                  import)) {
        return;
    }

    if (AddImportSpecifiersToTopBindings(specifier, global_bindings, import, record, std::move(viewed_re_export))) {
        return;
    }

    ASSERT(specifier->IsImportDefaultSpecifier());
    auto predicate_func = [](const auto &item) { return item.second->Declaration()->Node()->IsDefaultExported(); };

    auto item = std::find_if(global_bindings.begin(), global_bindings.end(), predicate_func);
    if (item == global_bindings.end()) {
        insert_foreign_binding(specifier->AsImportDefaultSpecifier()->Local()->Name(),
                               FindStaticBinding(record, import_path));
        return;
    }

    insert_foreign_binding(specifier->AsImportDefaultSpecifier()->Local()->Name(), item->second);
}

void ETSBinder::HandleCustomNodes(ir::AstNode *child_node)
{
    switch (child_node->Type()) {
        case ir::AstNodeType::ETS_TYPE_REFERENCE: {
            auto *type_ref = child_node->AsETSTypeReference();
            auto *base_name = type_ref->BaseName();
            ASSERT(base_name->IsReference());
            // We allow to resolve following types in pure dynamic mode:
            // import * as I from "@dynamic"
            // let x : I.X.Y
            bool allow_dynamic_namespaces = type_ref->Part()->Name() != base_name;
            LookupTypeReference(base_name, allow_dynamic_namespaces);
            LookupTypeArgumentReferences(type_ref);
            break;
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            BuildInterfaceDeclaration(child_node->AsTSInterfaceDeclaration());
            break;
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            ResolveEnumDeclaration(child_node->AsTSEnumDeclaration());
            break;
        }
        case ir::AstNodeType::EXPORT_NAMED_DECLARATION: {
            break;
        }
        case ir::AstNodeType::ETS_IMPORT_DECLARATION: {
            BuildImportDeclaration(child_node->AsETSImportDeclaration());
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            BuildMemberExpression(child_node->AsMemberExpression());
            break;
        }
        case ir::AstNodeType::METHOD_DEFINITION: {
            BuildMethodDefinition(child_node->AsMethodDefinition());
            break;
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            BuildETSNewClassInstanceExpression(child_node->AsETSNewClassInstanceExpression());
            break;
        }
        case ir::AstNodeType::ETS_FUNCTION_TYPE: {
            BuildSignatureDeclarationBaseParams(child_node);
            break;
        }
        default: {
            ResolveReferences(child_node);
            break;
        }
    }
}

bool ETSBinder::BuildInternalName(ir::ScriptFunction *script_func)
{
    if (script_func->IsArrow()) {
        return true;
    }

    auto *func_scope = script_func->Scope();
    func_scope->BindName(record_table_->RecordName());
    bool is_external = record_table_->IsExternal();

    bool compilable = script_func->Body() != nullptr && !is_external;
    if (!compilable) {
        record_table_->Signatures().push_back(func_scope);
    }

    if (is_external) {
        script_func->AddFlag(ir::ScriptFunctionFlags::EXTERNAL);
    }

    return compilable;
}

void ETSBinder::AddCompilableFunction(ir::ScriptFunction *func)
{
    if (func->IsArrow() || func->IsAsyncFunc()) {
        return;
    }

    AddCompilableFunctionScope(func->Scope());
}

void ETSBinder::BuildFunctionName(const ir::ScriptFunction *func) const
{
    auto *func_scope = func->Scope();

    std::stringstream ss;
    ASSERT(func->IsArrow() || !func_scope->Name().Empty());
    ss << func_scope->Name() << compiler::Signatures::METHOD_SEPARATOR;

    const auto *signature = func->Signature();

    if (func->IsStaticBlock()) {
        ss << compiler::Signatures::CCTOR;
    } else if (func->IsConstructor()) {
        ss << compiler::Signatures::CTOR;
    } else {
        if (func->IsGetter()) {
            ss << compiler::Signatures::GETTER_BEGIN;
        } else if (func->IsSetter()) {
            ss << compiler::Signatures::SETTER_BEGIN;
        }
        ss << util::Helpers::FunctionName(Allocator(), func);
    }

    signature->ToAssemblerType(GetCompilerContext(), ss);

    util::UString internal_name(ss.str(), Allocator());
    func_scope->BindInternalName(internal_name.View());
}

void ETSBinder::FormLambdaName(util::UString &name, const util::StringView &signature)
{
    name.Append(compiler::Signatures::LAMBDA_SEPARATOR);
    auto replaced = std::string(signature.Utf8());
    std::replace(replaced.begin(), replaced.end(), '.', '-');
    std::replace(replaced.begin(), replaced.end(), ':', '-');
    std::replace(replaced.begin(), replaced.end(), ';', '-');
    replaced.append(std::to_string(0));
    name.Append(replaced);
}

void ETSBinder::FormFunctionalInterfaceName(util::UString &name, const util::StringView &signature)
{
    auto replaced = std::string(signature.Utf8());
    std::replace(replaced.begin(), replaced.end(), '.', '-');
    std::replace(replaced.begin(), replaced.end(), ':', '-');
    std::replace(replaced.begin(), replaced.end(), ';', '-');
    replaced.append(std::to_string(0));
    name.Append(replaced);
}

void ETSBinder::BuildLambdaObjectName(const ir::AstNode *ref_node)
{
    auto found = lambda_objects_.find(ref_node);
    ASSERT(found != lambda_objects_.end());
    auto *lambda_class = found->second.first;
    auto *signature_ref = found->second.second;

    util::UString lambda_object_name(lambda_class->Ident()->Name(), Allocator());
    FormLambdaName(lambda_object_name, signature_ref->InternalName());
    lambda_class->Ident()->SetName(lambda_object_name.View());
    lambda_class->SetInternalName(lambda_class->Ident()->Name());

    util::StringView assembler_name(lambda_class->Ident()->Name());
    auto *program = static_cast<const ir::ETSScript *>(ref_node->GetTopStatement())->Program();
    util::StringView prefix = program->GetPackageName();
    if (!prefix.Empty()) {
        util::UString full_path(prefix, Allocator());
        full_path.Append('.');
        full_path.Append(assembler_name);
        assembler_name = full_path.View();
    }

    checker::ETSObjectType *lambda_object = lambda_class->TsType()->AsETSObjectType();
    lambda_object->SetName(lambda_class->Ident()->Name());
    lambda_object->SetAssemblerName(lambda_class->Ident()->Name());

    const auto &lambda_body = lambda_class->Body();
    auto *ctor_func = lambda_body[lambda_body.size() - 2]->AsMethodDefinition()->Function();
    auto *ctor_func_scope = ctor_func->Scope();
    ctor_func_scope->BindName(lambda_class->Ident()->Name());

    auto *invoke_func = lambda_body[lambda_body.size() - 1]->AsMethodDefinition()->Function();
    auto *invoke_func_scope = invoke_func->Scope();
    invoke_func_scope->BindName(lambda_class->Ident()->Name());
}

void ETSBinder::BuildFunctionalInterfaceName(ir::ETSFunctionType *func_type)
{
    auto *functional_interface = func_type->FunctionalInterface();
    auto *invoke_func = functional_interface->Body()->Body()[0]->AsMethodDefinition()->Function();
    util::UString functional_interface_name(functional_interface->Id()->Name(), Allocator());
    std::stringstream ss;
    invoke_func->Signature()->ToAssemblerType(GetCompilerContext(), ss);
    std::string signature_string = ss.str();
    util::StringView signature_name(signature_string);
    FormFunctionalInterfaceName(functional_interface_name, signature_name);
    functional_interface->Id()->SetName(functional_interface_name.View());
    util::UString internal_name(Program()->GetPackageName(), Allocator());
    if (!(internal_name.View().Empty())) {
        internal_name.Append(compiler::Signatures::METHOD_SEPARATOR);
    }
    internal_name.Append(functional_interface->Id()->Name());
    functional_interface->SetInternalName(internal_name.View());

    checker::ETSObjectType *functional_interface_type = functional_interface->TsType()->AsETSObjectType();
    functional_interface_type->SetName(functional_interface->Id()->Name());
    functional_interface_type->SetAssemblerName(internal_name.View());

    auto *invoke_func_scope = invoke_func->Scope();
    invoke_func_scope->BindName(functional_interface->Id()->Name());

    util::UString invoke_internal_name(Program()->GetPackageName(), Allocator());
    if (!(invoke_internal_name.View().Empty())) {
        invoke_internal_name.Append(compiler::Signatures::METHOD_SEPARATOR);
    }
    invoke_internal_name.Append(invoke_func_scope->Name());
    invoke_internal_name.Append(compiler::Signatures::METHOD_SEPARATOR);
    invoke_internal_name.Append(invoke_func->Id()->Name());
    std::stringstream invoke_signature_ss;
    invoke_func->Signature()->ToAssemblerType(GetCompilerContext(), invoke_signature_ss);
    invoke_internal_name.Append(invoke_signature_ss.str());
    invoke_func_scope->BindInternalName(invoke_internal_name.View());
}

void ETSBinder::InitImplicitThisParam()
{
    this_param_ = Allocator()->New<ir::Identifier>("this", Allocator());
}

void ETSBinder::BuildProgram()
{
    for (auto &[_, extPrograms] : Program()->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : extPrograms) {
            BuildExternalProgram(ext_prog);
        }
    }

    for (auto *default_import : default_imports_) {
        BuildImportDeclaration(default_import);
    }

    auto &stmts = Program()->Ast()->Statements();
    const auto ets_global = std::find_if(stmts.begin(), stmts.end(), [](const ir::Statement *stmt) {
        return stmt->IsClassDeclaration() &&
               stmt->AsClassDeclaration()->Definition()->Ident()->Name().Is(compiler::Signatures::ETS_GLOBAL);
    });
    if (ets_global != stmts.end()) {
        const auto begin = std::find_if(stmts.rbegin(), stmts.rend(), [](const ir::Statement *stmt) {
                               return stmt->IsETSImportDeclaration() || stmt->IsETSPackageDeclaration();
                           }).base();

        const size_t index = std::distance(begin, ets_global);
        std::rotate(begin, begin + index, begin + index + 1);
    }

    for (auto *stmt : stmts) {
        ResolveReference(stmt);
    }
}

void ETSBinder::BuildExternalProgram(parser::Program *ext_program)
{
    auto *saved_program = Program();
    auto *saved_record_table = record_table_;
    auto *saved_top_scope = TopScope();

    auto flags = Program()->VarBinder()->IsGenStdLib() ? RecordTableFlags::NONE : RecordTableFlags::EXTERNAL;
    auto *ext_record_table = Allocator()->New<RecordTable>(Allocator(), ext_program, flags);
    external_record_table_.insert({ext_program, ext_record_table});

    ResetTopScope(ext_program->GlobalScope());
    record_table_ = ext_record_table;
    SetProgram(ext_program);

    BuildProgram();

    SetProgram(saved_program);
    record_table_ = saved_record_table;
    ResetTopScope(saved_top_scope);
}

void ETSBinder::BuildETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *class_instance)
{
    BoundContext bound_ctx(record_table_, class_instance->ClassDefinition());
    ResolveReference(class_instance->GetTypeRef());

    for (auto *arg : class_instance->GetArguments()) {
        ResolveReference(arg);
    }

    if (class_instance->ClassDefinition() == nullptr) {
        return;
    }

    ResolveReference(class_instance->ClassDefinition());
}

void ETSBinder::BuildImportDeclaration(ir::ETSImportDeclaration *decl)
{
    if (decl->Source()->Str() == Program()->AbsoluteName()) {
        return;
    }

    auto specifiers = decl->Specifiers();

    for (auto specifier : specifiers) {
        AddSpecifiersToTopBindings(specifier, decl, decl->Source());
    }
}

bool ETSBinder::ImportGlobalPropertiesForNotDefaultedExports(varbinder::Variable *var, const util::StringView &name,
                                                             const ir::ClassElement *class_element)
{
    if (var->Declaration()->Node()->IsDefaultExported()) {
        return false;
    }

    const auto ins_res = TopScope()->InsertForeignBinding(name, var);
    if (!(!ins_res.second && ins_res.first != TopScope()->Bindings().end()) || !(ins_res.first->second != var)) {
        return true;
    }
    if (ins_res.first->second->Declaration()->IsFunctionDecl() && var->Declaration()->IsFunctionDecl()) {
        auto *const current_node = ins_res.first->second->Declaration()->Node();
        auto *const method = var->Declaration()->Node()->AsMethodDefinition();
        if (!current_node->AsMethodDefinition()->HasOverload(method)) {
            current_node->AsMethodDefinition()->AddOverload(method);
            method->Function()->Id()->SetVariable(ins_res.first->second);
            method->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
        }
        return true;
    }

    auto str = util::Helpers::AppendAll("Variable '", name.Utf8(), "'");
    if (ins_res.first->second->Declaration()->Type() == var->Declaration()->Type()) {
        str += " is already defined.";
    } else {
        str += " is already defined with different type.";
    }
    ThrowError(class_element->Id()->Start(), str);
}

void ETSBinder::ImportGlobalProperties(const ir::ClassDefinition *const class_def)
{
    const auto scope_ctx = LexicalScope<ClassScope>::Enter(this, class_def->Scope()->AsClassScope());

    for (const auto *const prop : class_def->Body()) {
        const auto *const class_element = prop->AsClassElement();

        if (class_element->IsClassStaticBlock()) {
            continue;
        }

        ASSERT(class_element->IsStatic());
        const auto &name = class_element->Id()->Name();
        auto *const var = scope_ctx.GetScope()->FindLocal(name, ResolveBindingOptions::ALL);
        ASSERT(var != nullptr);

        if (ImportGlobalPropertiesForNotDefaultedExports(var, name, class_element)) {
            return;
        }
    }
}

const DynamicImportData *ETSBinder::DynamicImportDataForVar(const Variable *var) const
{
    auto it = dynamic_import_vars_.find(var);
    if (it == dynamic_import_vars_.cend()) {
        return nullptr;
    }

    return &it->second;
}

bool ETSBinder::IsDynamicModuleVariable(const Variable *var) const
{
    auto *data = DynamicImportDataForVar(var);
    if (data == nullptr) {
        return false;
    }

    return data->specifier->IsImportSpecifier();
}

bool ETSBinder::IsDynamicNamespaceVariable(const Variable *var) const
{
    auto *data = DynamicImportDataForVar(var);
    if (data == nullptr) {
        return false;
    }

    return data->specifier->IsImportNamespaceSpecifier();
}

}  // namespace panda::es2panda::varbinder
