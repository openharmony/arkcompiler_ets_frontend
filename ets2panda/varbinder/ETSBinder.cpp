/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "evaluate/scopedDebugInfoPlugin.h"
#include "public/public.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::varbinder {

void ETSBinder::IdentifierAnalysis()
{
    ES2PANDA_ASSERT(Program()->Ast());
    ES2PANDA_ASSERT(GetScope() == TopScope());
    ES2PANDA_ASSERT(VarScope() == TopScope());

    recordTable_->SetProgram(Program());
    globalRecordTable_.SetClassDefinition(Program()->GlobalClass());
    BuildProgram();

    ES2PANDA_ASSERT(globalRecordTable_.ClassDefinition() == Program()->GlobalClass());
}

void ETSBinder::LookupTypeArgumentReferences(ir::ETSTypeReference *typeRef)
{
    auto *iter = typeRef->Part();
    for (auto *anno : typeRef->Annotations()) {
        ResolveReference(anno);
    }

    while (iter != nullptr) {
        if (iter->TypeParams() == nullptr) {
            iter = iter->Previous();
            continue;
        }

        ResolveReferences(iter->TypeParams());
        iter = iter->Previous();
    }
}

static bool IsSpecialName(const util::StringView &name)
{
    return name == compiler::Signatures::UNDEFINED || name == compiler::Signatures::NULL_LITERAL ||
           name == compiler::Signatures::READONLY_TYPE_NAME || name == compiler::Signatures::PARTIAL_TYPE_NAME ||
           name == compiler::Signatures::REQUIRED_TYPE_NAME || name == compiler::Signatures::FIXED_ARRAY_TYPE_NAME;
}

bool ETSBinder::HandleDynamicVariables(ir::Identifier *ident, Variable *variable, bool allowDynamicNamespaces)
{
    if (IsDynamicModuleVariable(variable)) {
        ident->SetVariable(variable);
        return true;
    }

    if (allowDynamicNamespaces && IsDynamicNamespaceVariable(variable)) {
        ident->SetVariable(variable);
        return true;
    }
    return false;
}

bool ETSBinder::LookupInDebugInfoPlugin(ir::Identifier *ident)
{
    auto *checker = GetContext()->checker->AsETSChecker();
    auto *debugInfoPlugin = checker->GetDebugInfoPlugin();
    if (UNLIKELY(debugInfoPlugin)) {
        auto *var = debugInfoPlugin->FindClass(ident);
        if (var != nullptr) {
            ident->SetVariable(var);
            return true;
        }
    }
    // NOTE: search an imported module's name in case of 'import "file" as xxx'.
    return false;
}

//  Auxiliary method extracted from LookupTypeReference(...) to avoid too large size
static void CreateDummyVariable(ETSBinder *varBinder, ir::Identifier *ident)
{
    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, varBinder->VarScope());
    auto [decl, var] =
        varBinder->NewVarDecl<varbinder::LetDecl>(ident->Start(), compiler::GenName(varBinder->Allocator()).View());
    var->SetScope(varBinder->GetScope());
    ident->SetVariable(var);
    ident->SetTsType(var->SetTsType(varBinder->GetContext()->checker->AsETSChecker()->GlobalTypeError()));
    decl->BindNode(ident);
}

void ETSBinder::LookupTypeReference(ir::Identifier *ident, bool allowDynamicNamespaces)
{
    if (ident->Variable() != nullptr && ident->Variable()->Declaration()->Node() == ident) {
        return;
    }

    auto const &name = ident->Name();
    if (IsSpecialName(name)) {
        return;
    }

    if (ident->IsErrorPlaceHolder()) {
        CreateDummyVariable(this, ident);
        return;
    }

    auto *scope = GetScope();
    while (scope != nullptr) {
        auto options = ResolveBindingOptions::DECLARATION | ResolveBindingOptions::TYPE_ALIASES |
                       ResolveBindingOptions::STATIC_DECLARATION;
        auto res = scope->Find(name, options);
        if (res.variable == nullptr) {
            break;
        }

        if (HandleDynamicVariables(ident, res.variable, allowDynamicNamespaces)) {
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
            case ir::AstNodeType::ANNOTATION_DECLARATION:
            case ir::AstNodeType::IMPORT_NAMESPACE_SPECIFIER: {
                ident->SetVariable(res.variable);
                return;
            }
            default: {
                scope = scope->Parent();
            }
        }
    }

    if (LookupInDebugInfoPlugin(ident)) {
        return;
    }

    ThrowUnresolvableType(ident->Start(), name);
    CreateDummyVariable(this, ident);
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
            if (ident->Variable() != nullptr) {
                break;
            }
            if (auto const res = scope->Find(ident->Name(), ResolveBindingOptions::ALL); res.variable != nullptr) {
                ident->SetVariable(res.variable);
            }
            break;
        }
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            auto scopeCtx = LexicalScope<Scope>::Enter(this, scope);
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
        case ir::AstNodeType::BLOCK_EXPRESSION: {
            auto scopeCtx = LexicalScope<Scope>::Enter(this, node->AsBlockExpression()->Scope());
            ResolveReferences(node);
            break;
        }
        default: {
            ResolveReferencesForScope(node, scope);
            break;
        }
    }
}

void ETSBinder::ResolveReferencesForScopeWithContext(ir::AstNode *node, Scope *scope)
{
    auto lexScope = LexicalScope<Scope>::Enter(this, scope);
    ResolveReference(node);
}

bool ETSBinder::AddSelectiveExportAlias(util::StringView const &path, util::StringView const &key,
                                        util::StringView const &value, ir::AstNode const *decl) noexcept
{
    if (auto foundMap = selectiveExportAliasMultimap_.find(path); foundMap != selectiveExportAliasMultimap_.end()) {
        return foundMap->second.insert({key, std::make_pair(value, decl)}).second;
    }

    ArenaMap<util::StringView, std::pair<util::StringView, ir::AstNode const *>> map(Allocator()->Adapter());
    bool insertResult = map.insert({key, std::make_pair(value, decl)}).second;
    selectiveExportAliasMultimap_.insert({path, map});
    return insertResult;
}

util::StringView ETSBinder::FindNameInAliasMap(const util::StringView &pathAsKey, const util::StringView &aliasName)
{
    if (auto relatedMap = selectiveExportAliasMultimap_.find(pathAsKey);
        relatedMap != selectiveExportAliasMultimap_.end()) {
        if (auto item = relatedMap->second.find(aliasName); item != relatedMap->second.end()) {
            return item->second.first;
        }
    }

    return "";
}

const ir::AstNode *ETSBinder::FindNodeInAliasMap(const util::StringView &pathAsKey, const util::StringView &aliasName)
{
    if (auto relatedMap = selectiveExportAliasMultimap_.find(pathAsKey);
        relatedMap != selectiveExportAliasMultimap_.end()) {
        if (auto item = relatedMap->second.find(aliasName); item != relatedMap->second.end()) {
            return item->second.second;
        }
    }

    return nullptr;
}

void ETSBinder::LookupIdentReference(ir::Identifier *ident)
{
    if (ident->IsErrorPlaceHolder()) {
        return;
    }

    const auto &name = ident->Name();
    auto res = GetScope()->Find(name, ResolveBindingOptions::ALL);
    if (res.level != 0) {
        ES2PANDA_ASSERT(res.variable != nullptr);

        auto *outerFunction = GetScope()->EnclosingVariableScope()->Node();

        if ((!outerFunction->IsScriptFunction() || !outerFunction->AsScriptFunction()->IsArrow()) &&
            !res.variable->IsGlobalVariable() && res.variable->HasFlag(VariableFlags::LOCAL) && res.level > 1) {
            ThrowInvalidCapture(ident->Start(), name);
        }
    }

    if (res.variable == nullptr) {
        return;
    }

    if (ident->IsReference(Extension()) && res.variable->Declaration()->IsLetOrConstDecl() &&
        !res.variable->HasFlag(VariableFlags::INITIALIZED)) {
        ThrowTDZ(ident->Start(), name);
    }
}

void ETSBinder::BuildClassProperty(const ir::ClassProperty *prop)
{
    ResolveReferences(prop);
}

void ETSBinder::BuildETSTypeReference(ir::ETSTypeReference *typeRef)
{
    auto *baseName = typeRef->BaseName();
    ES2PANDA_ASSERT(baseName->IsReference(Extension()));

    // We allow to resolve following types in pure dynamic mode:
    // import * as I from "@dynamic"
    // let x : I.X.Y
    bool allowDynamicNamespaces = typeRef->Part()->Name() != baseName;
    LookupTypeReference(baseName, allowDynamicNamespaces);
    LookupTypeArgumentReferences(typeRef);
}

void ETSBinder::BuildObjectExpression(ir::ObjectExpression *obj)
{
    for (auto *it : obj->Decorators()) {
        ResolveReference(it);
    }

    // NOTE: when we try to resolve references for Object Expression
    // we visit properties, example:
    // class C { x : boolean }
    // let x: C = { x: true }
    //
    // However we visit Object Expression with _outer_ scope, not class scope.
    // That means that varbinder will try to resolve `x` as `x` from outer scope, _not from the class scope_.
    // The following code will skip resolving LHS of the property.
    // We can do it because currently LHS is still checked in the `ETSAnalyzer::CheckObjectExprProps` function.
    for (auto expr : obj->Properties()) {
        if (expr->IsProperty()) {
            auto *prop = expr->AsProperty();
            ResolveReference(prop->Value());
        }
    }

    if (obj->TypeAnnotation() != nullptr) {
        ResolveReference(obj->TypeAnnotation());
    }
}

void ETSBinder::InitializeInterfaceIdent(ir::TSInterfaceDeclaration *decl)
{
    auto res = GetScope()->Find(decl->Id()->Name());

    ES2PANDA_ASSERT(res.variable && res.variable->Declaration()->IsInterfaceDecl());
    res.variable->AddFlag(VariableFlags::INITIALIZED);
    decl->Id()->SetVariable(res.variable);
}

void ETSBinder::ResolveEnumDeclaration(ir::TSEnumDeclaration *enumDecl)
{
    auto enumScopeCtx = LexicalScope<LocalScope>::Enter(this, enumDecl->Scope());

    for (auto *member : enumDecl->Members()) {
        ResolveReference(member);
    }
}

void ETSBinder::ResolveInterfaceDeclaration(ir::TSInterfaceDeclaration *decl)
{
    auto boundCtx = BoundContext(recordTable_, decl);

    for (auto *extend : decl->Extends()) {
        ResolveReference(extend);
    }

    for (auto *anno : decl->Annotations()) {
        ResolveReference(anno);
    }

    auto scopeCtx = LexicalScope<ClassScope>::Enter(this, decl->Scope()->AsClassScope());

    for (auto *stmt : decl->Body()->Body()) {
        if (!stmt->IsClassProperty()) {
            continue;
        }

        ResolveReference(stmt);

        auto fieldVar =
            ResolvePropertyReference(stmt->AsClassProperty(), decl->Scope()->AsClassScope())
                ->FindLocal(stmt->AsClassProperty()->Id()->Name(), varbinder::ResolveBindingOptions::BINDINGS);
        fieldVar->AddFlag(VariableFlags::INITIALIZED);
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
        auto typeParamScopeCtx = LexicalScope<LocalScope>::Enter(this, decl->TypeParams()->Scope());
        ResolveReferences(decl->TypeParams());
        ResolveInterfaceDeclaration(decl);
        return;
    }

    ResolveInterfaceDeclaration(decl);
}

void ETSBinder::BuildMethodDefinition(ir::MethodDefinition *methodDef)
{
    if (methodDef->Function()->TypeParams() != nullptr) {
        auto scopeCtx = LexicalScope<LocalScope>::Enter(this, methodDef->Function()->TypeParams()->Scope());
        ResolveReferences(methodDef->Function()->TypeParams());
    }
    ResolveMethodDefinition(methodDef);
}

void ETSBinder::BuildAnnotationDeclaration(ir::AnnotationDeclaration *annoDecl)
{
    auto boundCtx = BoundContext(recordTable_, annoDecl);
    if (annoDecl->Expr()->IsIdentifier()) {
        LookupTypeReference(annoDecl->AsAnnotationDeclaration()->Expr()->AsIdentifier(), false);
    } else {
        ResolveReference(annoDecl->Expr());
    }
    auto scopeCtx = LexicalScope<LocalScope>::Enter(this, annoDecl->Scope());
    for (auto *property : annoDecl->Properties()) {
        ResolveReference(property);
    }
    for (auto *anno : annoDecl->Annotations()) {
        ResolveReference(anno);
    }
}

void ETSBinder::BuildAnnotationUsage(ir::AnnotationUsage *annoUsage)
{
    if (annoUsage->Expr()->IsIdentifier()) {
        LookupTypeReference(annoUsage->AsAnnotationUsage()->Expr()->AsIdentifier(), false);
    } else {
        ResolveReference(annoUsage->Expr());
    }

    for (auto *property : annoUsage->Properties()) {
        ResolveReference(property);
    }
}

void ETSBinder::ResolveMethodDefinition(ir::MethodDefinition *methodDef)
{
    methodDef->ResolveReferences([this](auto *childNode) { ResolveReference(childNode); });

    auto *func = methodDef->Function();
    for (auto *anno : func->Annotations()) {
        ResolveReference(anno);
    }
    if (methodDef->IsStatic() || func->IsStaticBlock()) {
        return;
    }

    auto paramScopeCtx = LexicalScope<FunctionParamScope>::Enter(this, func->Scope()->ParamScope());

    auto params = func->Scope()->ParamScope()->Params();
    if (!params.empty() && params.front()->Name() == MANDATORY_PARAM_THIS && !func->HasReceiver()) {
        return;  // Implicit this parameter is already inserted by ResolveReferences(), don't insert it twice.
    }

    auto *thisParam = AddMandatoryParam(MANDATORY_PARAM_THIS);
    thisParam->Declaration()->BindNode(thisParam_);
}

void ETSBinder::BuildMemberExpression(ir::MemberExpression *memberExpr)
{
    ResolveReference(memberExpr->Object());

    if (memberExpr->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS) {
        ResolveReference(memberExpr->Property());
    }
}

void ETSBinder::BuildClassDefinition(ir::ClassDefinition *classDef)
{
    auto boundCtx = BoundContext(recordTable_, classDef);

    if (classDef->TypeParams() != nullptr) {
        auto scopeCtx = LexicalScope<LocalScope>::Enter(this, classDef->TypeParams()->Scope());
        ResolveReferences(classDef->TypeParams());
        BuildClassDefinitionImpl(classDef);
        return;
    }

    BuildClassDefinitionImpl(classDef);
}

LocalScope *ETSBinder::ResolvePropertyReference(ir::ClassProperty *prop, ClassScope *scope)
{
    ResolveReferences(prop);

    if (prop->IsStatic()) {
        return scope->StaticFieldScope();
    }

    return scope->InstanceFieldScope();
}

void ETSBinder::BuildClassDefinitionImpl(ir::ClassDefinition *classDef)
{
    auto classCtx = LexicalScope<ClassScope>::Enter(this, classDef->Scope()->AsClassScope());

    if (classDef->Super() != nullptr) {
        ResolveReference(classDef->Super());
    }

    for (auto *impl : classDef->Implements()) {
        ResolveReference(impl);
    }
    for (auto *anno : classDef->Annotations()) {
        ResolveReference(anno);
    }

    for (auto *stmt : classDef->Body()) {
        if (!stmt->IsClassProperty()) {
            continue;
        }
        auto *const prop = stmt->AsClassProperty();

        auto fieldScope = ResolvePropertyReference(prop, classDef->Scope()->AsClassScope());
        auto fieldName = prop->Id()->Name();
        if (auto fieldVar = fieldScope->FindLocal(fieldName, varbinder::ResolveBindingOptions::BINDINGS);
            fieldVar != nullptr) {
            fieldVar->AddFlag(VariableFlags::INITIALIZED);
            if ((fieldVar->Declaration()->IsConstDecl() || fieldVar->Declaration()->IsReadonlyDecl()) &&
                prop->Value() == nullptr) {
                fieldVar->AddFlag(VariableFlags::EXPLICIT_INIT_REQUIRED);
            }
        } else {
            ES2PANDA_ASSERT(GetContext()->diagnosticEngine->IsAnyError());
            auto *checker = GetContext()->checker->AsETSChecker();
            prop->SetTsType(checker->GlobalTypeError());
            prop->Id()->SetTsType(checker->GlobalTypeError());
        }
    }

    for (auto *stmt : classDef->Body()) {
        if (stmt->IsClassProperty()) {
            continue;
        }
        ResolveReference(stmt);
    }
}

void ETSBinder::AddFunctionThisParam(ir::ScriptFunction *func)
{
    auto paramScopeCtx = LexicalScope<FunctionParamScope>::Enter(this, func->Scope()->ParamScope());
    auto *thisParam = AddMandatoryParam(MANDATORY_PARAM_THIS);
    thisParam->Declaration()->BindNode(thisParam_);
}

void ETSBinder::AddDynamicImport(ir::ETSImportDeclaration *import)
{
    ES2PANDA_ASSERT(import->Language().IsDynamic());
    dynamicImports_.push_back(import);
}

void ETSBinder::BuildProxyMethod(ir::ScriptFunction *func, const util::StringView &containingClassName, bool isExternal)
{
    ES2PANDA_ASSERT(!containingClassName.Empty());
    func->Scope()->BindName(containingClassName);

    if (!func->IsAsyncFunc() && !isExternal) {
        Functions().push_back(func->Scope());
    }
}

void ETSBinder::AddDynamicSpecifiersToTopBindings(ir::AstNode *const specifier,
                                                  const ir::ETSImportDeclaration *const import)
{
    // NOTE issue #23214: enable it after fix default import in dynamic import
    if (specifier->IsImportDefaultSpecifier()) {
        ThrowError(specifier->Start(), "Default import is currently not implemented in dynamic import");
        return;
    }
    const auto name = [specifier]() {
        if (specifier->IsImportNamespaceSpecifier()) {
            return specifier->AsImportNamespaceSpecifier()->Local()->Name();
        }

        return specifier->AsImportSpecifier()->Local()->Name();
    }();

    auto specDecl = GetScope()->Find(name, ResolveBindingOptions::DECLARATION);
    ES2PANDA_ASSERT(specDecl.variable != nullptr);
    dynamicImportVars_.emplace(specDecl.variable, DynamicImportData {import, specifier, specDecl.variable});

    if (specifier->IsImportSpecifier()) {
        auto importSpecifier = specifier->AsImportSpecifier();
        importSpecifier->Imported()->SetVariable(specDecl.variable);
        importSpecifier->Local()->SetVariable(specDecl.variable);
    }
}

void ETSBinder::InsertForeignBinding(ir::AstNode *const specifier, const ir::ETSImportDeclaration *const import,
                                     const util::StringView &name, Variable *var)
{
    if (import->Language().IsDynamic()) {
        dynamicImportVars_.emplace(var, DynamicImportData {import, specifier, var});
    }

    TopScope()->InsertForeignBinding(name, var);
}

void ETSBinder::InsertOrAssignForeignBinding(ir::AstNode *const specifier, const ir::ETSImportDeclaration *const import,
                                             const util::StringView &name, Variable *var)
{
    if (import->Language().IsDynamic()) {
        dynamicImportVars_.insert_or_assign(var, DynamicImportData {import, specifier, var});
    }

    TopScope()->InsertOrAssignForeignBinding(name, var);
}

std::string RedeclarationErrorMessageAssembler(const Variable *const var, const Variable *const variable,
                                               util::StringView localName)
{
    bool isNamespace = var->Declaration()->Node()->IsClassDefinition() &&
                       var->Declaration()->Node()->AsClassDefinition()->IsNamespaceTransformed();
    auto type = isNamespace                                       ? "Namespace '"
                : var->Declaration()->Node()->IsClassDefinition() ? "Class '"
                : var->Declaration()->IsFunctionDecl()            ? "Function '"
                                                                  : "Variable '";
    auto str = util::Helpers::AppendAll(type, localName.Utf8(), "'");
    str += variable->Declaration()->Type() == var->Declaration()->Type() ? " is already defined."
                                                                         : " is already defined with different type.";

    return str;
}

void AddOverloadFlag(ArenaAllocator *allocator, bool isStdLib, varbinder::Variable *importedVar,
                     varbinder::Variable *variable)
{
    auto *const currentNode = variable->Declaration()->Node()->AsMethodDefinition();
    auto *const method = importedVar->Declaration()->Node()->AsMethodDefinition();

    // Necessary because stdlib and escompat handled as same package, it can be removed after fixing package handling
    auto const getPackageName = [](Variable *var) {
        return var->GetScope()->Node()->GetTopStatement()->AsETSModule()->Program()->ModuleName();
    };
    if (isStdLib && (getPackageName(importedVar) != getPackageName(variable))) {
        return;
    }

    if (!method->Overloads().empty() && !method->HasOverload(currentNode)) {
        method->AddOverload(currentNode);
        currentNode->Function()->Id()->SetVariable(importedVar);
        currentNode->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
        currentNode->Function()->AddFlag(ir::ScriptFunctionFlags::EXTERNAL_OVERLOAD);
        util::UString newInternalName(currentNode->Function()->Scope()->Name(), allocator);
        currentNode->Function()->Scope()->BindInternalName(newInternalName.View());
        return;
    }

    if (!currentNode->HasOverload(method)) {
        currentNode->AddOverload(method);
        method->Function()->Id()->SetVariable(variable);
        method->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
        method->Function()->AddFlag(ir::ScriptFunctionFlags::EXTERNAL_OVERLOAD);
        util::UString newInternalName(method->Function()->Scope()->Name(), allocator);
        method->Function()->Scope()->BindInternalName(newInternalName.View());
    }
}

void ETSBinder::ImportAllForeignBindings(ir::AstNode *const specifier,
                                         const varbinder::Scope::VariableMap &globalBindings,
                                         const parser::Program *const importProgram,
                                         const varbinder::GlobalScope *const importGlobalScope,
                                         const ir::ETSImportDeclaration *const import)
{
    bool const isStdLib = util::Helpers::IsStdLib(Program());

    for (const auto [bindingName, var] : globalBindings) {
        if (bindingName.Is(compiler::Signatures::ETS_GLOBAL)) {
            const auto *const classDef = var->Declaration()->Node()->AsClassDeclaration()->Definition();
            ImportGlobalProperties(classDef);
            continue;
        }
        ES2PANDA_ASSERT(bindingName.Utf8().find(compiler::Signatures::ETS_GLOBAL) == std::string::npos);

        if (!importGlobalScope->IsForeignBinding(bindingName) && !var->Declaration()->Node()->IsDefaultExported() &&
            (var->AsLocalVariable()->Declaration()->Node()->IsExported() ||
             var->AsLocalVariable()->Declaration()->Node()->IsExportedType())) {
            auto variable = Program()->GlobalClassScope()->FindLocal(bindingName, ResolveBindingOptions::ALL);
            if (variable == nullptr || var == variable) {
                InsertForeignBinding(specifier, import, bindingName, var);
                continue;
            }

            if (variable->Declaration()->IsFunctionDecl() && var->Declaration()->IsFunctionDecl()) {
                AddOverloadFlag(Allocator(), isStdLib, var, variable);
                continue;
            }

            // It will be a redeclaration error, but the imported element has not been placed among the bindings yet
            if (TopScope()->FindLocal(bindingName, ResolveBindingOptions::ALL) == nullptr) {
                InsertForeignBinding(specifier, import, bindingName, var);
            }

            // redeclaration for builtin type,
            // need to erase the redeclaration one and make sure the builtin types initialized successfully.
            if (var->HasFlag(varbinder::VariableFlags::BUILTIN_TYPE)) {
                TopScope()->CorrectForeignBinding(bindingName, var, variable);
            }

            ThrowError(import->Source()->Start(), RedeclarationErrorMessageAssembler(var, variable, bindingName));
        }
    }

    for (const auto [bindingName, var] : importProgram->GlobalClassScope()->StaticMethodScope()->Bindings()) {
        if (!var->Declaration()->Node()->IsDefaultExported()) {
            InsertForeignBinding(specifier, import, bindingName, var);
        }
    }

    for (const auto [bindingName, var] : importProgram->GlobalClassScope()->StaticFieldScope()->Bindings()) {
        if (!var->Declaration()->Node()->IsDefaultExported()) {
            InsertForeignBinding(specifier, import, bindingName, var);
        }
    }
}

bool ETSBinder::ReexportPathMatchesImportPath(const ir::ETSReExportDeclaration *const reexport,
                                              const ir::ETSImportDeclaration *const import) const
{
    // NOTE(dkofanov): Related to #23877. Probably this should be resolved by 'import->ResolvedSource()'.
    // For static import `ResolvedSource` is realpath, while in case of dynamic it module-relative.
    auto importSource = import->ImportMetadata().HasSpecifiedDeclPath() ? import->DeclPath() : import->ResolvedSource();
    auto reexportSource = reexport->GetProgramPath();
    return reexportSource == importSource;
}

static auto GetExternalProgram(ETSBinder *binder, const ir::ETSImportDeclaration *const import)
{
    if (!import->DeclPath().empty() && (import->DeclPath() != util::ImportPathManager::DUMMY_PATH)) {
        return binder->GetExternalProgram(std::string_view {import->DeclPath()}, import->Source());
    }
    return binder->GetExternalProgram(import->ResolvedSource(), import->Source());
}

void ETSBinder::AddImportNamespaceSpecifiersToTopBindings(Span<parser::Program *const> records,
                                                          ir::ImportNamespaceSpecifier *const namespaceSpecifier,
                                                          const ir::ETSImportDeclaration *const import)
{
    const parser::Program *const importProgram = records[0];
    const auto *const importGlobalScope = importProgram->GlobalScope();
    const auto &globalBindings = importGlobalScope->Bindings();

    if (namespaceSpecifier->Local()->Name().Empty()) {
        ImportAllForeignBindings(namespaceSpecifier, globalBindings, importProgram, importGlobalScope, import);
    }

    for (auto item : ReExportImports()) {
        // NOTE(rsipka): this should be refactored or eliminated
        if (!ReexportPathMatchesImportPath(item, import)) {
            continue;
        }

        for (auto it : item->GetETSImportDeclarations()->Specifiers()) {
            if (it->IsImportNamespaceSpecifier() && !namespaceSpecifier->Local()->Name().Empty()) {
                continue;
            }

            AddSpecifiersToTopBindings(it, item->GetETSImportDeclarations());
        }
    }
}

Variable *ETSBinder::FindImportSpecifiersVariable(const util::StringView &imported,
                                                  const varbinder::Scope::VariableMap &globalBindings,
                                                  Span<parser::Program *const> records)
{
    auto foundVar = globalBindings.find(imported);
    if (foundVar == globalBindings.end()) {
        const auto &staticMethodBindings = records[0]->GlobalClassScope()->StaticMethodScope()->Bindings();
        foundVar = staticMethodBindings.find(imported);
        if (foundVar != staticMethodBindings.end()) {
            return foundVar->second;
        }
        bool found = false;
        for (auto res : records) {
            const auto &staticFieldBindings = res->GlobalClassScope()->StaticFieldScope()->Bindings();
            foundVar = staticFieldBindings.find(imported);
            if (foundVar != staticFieldBindings.end()) {
                found = true;
                foundVar->second->AsLocalVariable()->AddFlag(VariableFlags::INITIALIZED);
                break;
            }
        }
        if (!found) {
            return nullptr;
        }
    }

    return foundVar->second;
}

static bool IsExportedVariable(varbinder::Variable *const var)
{
    return var != nullptr &&
           (var->Declaration()->Node()->IsExported() || var->Declaration()->Node()->IsExportedType() ||
            var->Declaration()->Node()->IsDefaultExported());
}

ir::ETSImportDeclaration *ETSBinder::FindImportDeclInReExports(const ir::ETSImportDeclaration *const import,
                                                               const util::StringView &imported,
                                                               const ir::StringLiteral *const importPath)
{
    ir::ETSImportDeclaration *implDecl = nullptr;
    for (auto item : ReExportImports()) {
        if (!ReexportPathMatchesImportPath(item, import)) {
            continue;
        }

        auto specifiers = item->GetETSImportDeclarations()->Specifiers();
        if (specifiers[0]->IsImportSpecifier()) {
            if (!std::any_of(specifiers.begin(), specifiers.end(), [&imported](auto it) {
                    return it->AsImportSpecifier()->Local()->Name().Is(imported.Mutf8());
                })) {
                continue;
            }
            implDecl = item->GetETSImportDeclarations();
        } else {
            const auto records = GetExternalProgram(item->GetETSImportDeclarations()->ResolvedSource(), importPath);
            if (records.empty()) {
                continue;
            }
            auto *const var =
                FindImportSpecifiersVariable(imported, records[0]->GlobalScope()->Bindings(), Span {records});
            if (IsExportedVariable(var)) {
                implDecl = item->GetETSImportDeclarations();
                continue;
            }
            auto reExportImport = item->GetETSImportDeclarations();
            auto reExportImportPath = reExportImport->Source();
            auto implDeclOrNullptr = FindImportDeclInReExports(reExportImport, imported, reExportImportPath);
            if (implDeclOrNullptr != nullptr) {
                implDecl = implDeclOrNullptr;
            }
        }
    }
    return implDecl;
}

void ETSBinder::ValidateImportVariable(const ir::AstNode *node, const ir::ETSImportDeclaration *const import,
                                       const util::StringView &imported, const ir::StringLiteral *const importPath)
{
    if (node->IsDefaultExported()) {
        ThrowError(importPath->Start(), "Use the default import syntax to import a default exported element");
    } else if (import->IsTypeKind() && !node->IsExportedType()) {
        ThrowError(importPath->Start(),
                   "Cannot import '" + imported.Mutf8() + "', imported type imports only exported types.");
    } else if (!node->IsExported() && !node->IsExportedType() && !node->IsDefaultExported()) {
        ThrowError(importPath->Start(), "Imported element not exported '" + imported.Mutf8() + "'");
    }
}

bool ETSBinder::DetectNameConflict(const util::StringView localName, Variable *const var, Variable *const otherVar,
                                   const ir::StringLiteral *const importPath)
{
    if (otherVar == nullptr || var == otherVar) {
        return false;
    }

    if (var->Declaration()->IsFunctionDecl() && otherVar->Declaration()->IsFunctionDecl()) {
        AddOverloadFlag(Allocator(), util::Helpers::IsStdLib(Program()), var, otherVar);
        return true;
    }

    bool isAmbient = var->Declaration()->Node()->IsDeclare() && !otherVar->Declaration()->Node()->IsDeclare();
    if (isAmbient) {
        return false;
    }

    ThrowError(importPath->Start(), RedeclarationErrorMessageAssembler(var, otherVar, localName));
    return true;
}

// CC-OFFNXT(huge_method, G.FUN.01-CPP) solid logic
bool ETSBinder::AddImportSpecifiersToTopBindings(Span<parser::Program *const> records,
                                                 ir::ImportSpecifier *const importSpecifier,
                                                 const ir::ETSImportDeclaration *const import)
{
    const auto &globalBindings = records[0]->GlobalScope()->Bindings();
    const ir::StringLiteral *const importPath = import->Source();

    if (!importSpecifier->Imported()->IsIdentifier()) {
        return true;
    }

    auto imported = importSpecifier->Imported()->Name();

    for (auto const item : import->Specifiers()) {
        if (item->IsImportSpecifier() && item->AsImportSpecifier()->Local()->Name().Is(imported.Mutf8()) &&
            !item->AsImportSpecifier()->Local()->Name().Is(item->AsImportSpecifier()->Imported()->Name().Mutf8())) {
            imported = item->AsImportSpecifier()->Imported()->Name();
        }
    }

    util::StringView nameToSearchFor = FindNameInAliasMap(import->ResolvedSource(), imported);
    if (nameToSearchFor.Empty()) {
        nameToSearchFor = imported;
    }

    auto *const var = FindImportSpecifiersVariable(nameToSearchFor, globalBindings, records);
    importSpecifier->Imported()->SetVariable(var);
    importSpecifier->Local()->SetVariable(var);

    if (var == nullptr) {
        ir::ETSImportDeclaration *implDecl = FindImportDeclInReExports(import, imported, importPath);
        if (implDecl != nullptr) {
            AddSpecifiersToTopBindings(importSpecifier, implDecl);
            return true;
        }

        ThrowError(importPath->Start(), "Cannot find imported element '" + imported.Mutf8() + "'");
        return false;
    }

    auto *node = FindNodeInAliasMap(import->ResolvedSource(), imported);

    ValidateImportVariable(node != nullptr ? node : var->Declaration()->Node(), import, imported, importPath);

    const auto localName = importSpecifier->Local()->Name();
    auto varInGlobalClassScope = Program()->GlobalClassScope()->FindLocal(localName, ResolveBindingOptions::ALL);
    auto previouslyImportedVariable = TopScope()->FindLocal(localName, ResolveBindingOptions::ALL);
    if (DetectNameConflict(localName, var, varInGlobalClassScope, importPath) ||
        DetectNameConflict(localName, var, previouslyImportedVariable, importPath)) {
        return true;
    }

    if (var->Declaration()->Node()->IsAnnotationDeclaration() &&
        var->Declaration()->Node()->AsAnnotationDeclaration()->GetBaseName()->Name() != localName) {
        ThrowError(importPath->Start(), "Can not rename annotation '" + var->Declaration()->Name().Mutf8() +
                                            "' in export or import statements.");
        return false;
    }

    // The first part of the condition will be true, if something was given an alias when exported, but we try
    // to import it using its original name.
    if (nameToSearchFor == imported && var->Declaration()->Node()->HasExportAlias()) {
        ThrowError(importSpecifier->Start(), "Cannot find imported element '" + imported.Mutf8() + "'");
        return false;
    }

    InsertOrAssignForeignBinding(importSpecifier, import, localName, var);
    return true;
}

void ETSBinder::AddImportDefaultSpecifiersToTopBindings(Span<parser::Program *const> records,
                                                        ir::ImportDefaultSpecifier *const importDefaultSpecifier,
                                                        const ir::ETSImportDeclaration *const import)
{
    auto importProgram = records[0];
    const auto &globalBindings = importProgram->GlobalScope()->Bindings();
    auto isDefaultExpored = [](const auto &item) { return item.second.second->IsDefaultExported(); };
    auto selectMap = importProgram->VarBinder()->AsETSBinder()->GetSelectiveExportAliasMultimap();
    auto selectMap2 = selectMap.find(import->ResolvedSource());
    if (selectMap2 != selectMap.end()) {
        auto item1 = std::find_if(selectMap2->second.begin(), selectMap2->second.end(), isDefaultExpored);
        if (item1 != selectMap2->second.end()) {
            auto item2 = FindImportSpecifiersVariable(item1->first, globalBindings, records);
            importDefaultSpecifier->Local()->SetVariable(item2);
            InsertForeignBinding(importDefaultSpecifier, import, importDefaultSpecifier->Local()->Name(), item2);
            return;
        }
    }

    if (auto var = FindStaticBinding(records, import->Source()); var != nullptr) {
        importDefaultSpecifier->Local()->SetVariable(var);
        InsertForeignBinding(importDefaultSpecifier, import, importDefaultSpecifier->Local()->Name(), var);
        return;
    }
}

static Variable *FindInStatic(parser::Program *program)
{
    auto predicateFunc = [](const auto &item) { return item.second->Declaration()->Node()->IsDefaultExported(); };
    const auto &staticMethodBindings = program->GlobalClassScope()->StaticMethodScope()->Bindings();
    auto result = std::find_if(staticMethodBindings.begin(), staticMethodBindings.end(), predicateFunc);
    if (result == staticMethodBindings.end()) {
        const auto &staticFieldBindings = program->GlobalClassScope()->StaticFieldScope()->Bindings();
        result = std::find_if(staticFieldBindings.begin(), staticFieldBindings.end(), predicateFunc);
        if (result == staticFieldBindings.end()) {
            const auto &staticDeclBindings = program->GlobalClassScope()->StaticDeclScope()->Bindings();
            result = std::find_if(staticDeclBindings.begin(), staticDeclBindings.end(), predicateFunc);
            if (result == staticDeclBindings.end()) {
                return nullptr;
            }
        }
    }
    return result->second;
}

static Variable *FindInInstance(parser::Program *program)
{
    auto predicateFunc = [](const auto &item) { return item.second->Declaration()->Node()->IsDefaultExported(); };
    const auto &instanceMethodBindings = program->GlobalClassScope()->InstanceMethodScope()->Bindings();
    auto result = std::find_if(instanceMethodBindings.begin(), instanceMethodBindings.end(), predicateFunc);
    if (result == instanceMethodBindings.end()) {
        const auto &instanceFieldBindings = program->GlobalClassScope()->InstanceFieldScope()->Bindings();
        result = std::find_if(instanceFieldBindings.begin(), instanceFieldBindings.end(), predicateFunc);
        if (result == instanceFieldBindings.end()) {
            const auto &instanceDeclBindings = program->GlobalClassScope()->InstanceDeclScope()->Bindings();
            result = std::find_if(instanceDeclBindings.begin(), instanceDeclBindings.end(), predicateFunc);
            if (result == instanceDeclBindings.end()) {
                return nullptr;
            }
        }
    }
    return result->second;
}

varbinder::Variable *ETSBinder::FindStaticBinding(Span<parser::Program *const> records,
                                                  const ir::StringLiteral *const importPath)
{
    auto result = FindInInstance(records[0]);
    if (result != nullptr) {
        return result;
    }
    result = FindInStatic(records[0]);
    if (result != nullptr) {
        return result;
    }
    ThrowError(importPath->Start(), "Cannot find default imported element in the target");
    return nullptr;
}

ArenaVector<parser::Program *> ETSBinder::GetExternalProgram(util::StringView sourceName,
                                                             const ir::StringLiteral *importPath)
{
    if (sourceName == ERROR_LITERAL) {
        // avoid logging rediculus messages, there must be a syntax error
        ES2PANDA_ASSERT(GetContext()->diagnosticEngine->IsAnyError());
        return ArenaVector<parser::Program *>(Allocator()->Adapter());
    }
    // NOTE: quick fix to make sure not to look for the global program among the external sources
    if (sourceName.Compare(globalRecordTable_.Program()->AbsoluteName()) == 0) {
        ArenaVector<parser::Program *> mainModule(Allocator()->Adapter());
        mainModule.emplace_back(globalRecordTable_.Program());
        return mainModule;
    }

    auto programList = GetProgramList(sourceName);
    if (programList.empty()) {
        if (ark::os::file::File::IsDirectory(sourceName.Mutf8())) {
            ThrowError(importPath->Start(),
                       "Cannot find index.[ets|ts] or package module in folder: " + importPath->Str().Mutf8());
        } else {
            ThrowError(importPath->Start(), "Cannot find import: " + importPath->Str().Mutf8());
        }
    }

    return programList;
}

void ETSBinder::AddSpecifiersToTopBindings(ir::AstNode *const specifier, const ir::ETSImportDeclaration *const import)
{
    if (import->IsPureDynamic()) {
        AddDynamicSpecifiersToTopBindings(specifier, import);
        return;
    }
    const auto records = varbinder::GetExternalProgram(this, import);
    if (records.empty()) {
        return;
    }

    if (specifier->IsImportNamespaceSpecifier()) {
        AddImportNamespaceSpecifiersToTopBindings(Span {records}, specifier->AsImportNamespaceSpecifier(), import);
    } else if (specifier->IsImportSpecifier()) {
        AddImportSpecifiersToTopBindings(Span {records}, specifier->AsImportSpecifier(), import);
    } else if (specifier->IsImportDefaultSpecifier()) {
        AddImportDefaultSpecifiersToTopBindings(Span {records}, specifier->AsImportDefaultSpecifier(), import);
    }
}

void ETSBinder::HandleCustomNodes(ir::AstNode *childNode)
{
    switch (childNode->Type()) {
        case ir::AstNodeType::ETS_TYPE_REFERENCE: {
            return BuildETSTypeReference(childNode->AsETSTypeReference());
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            return BuildInterfaceDeclaration(childNode->AsTSInterfaceDeclaration());
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            return ResolveEnumDeclaration(childNode->AsTSEnumDeclaration());
        }
        case ir::AstNodeType::EXPORT_NAMED_DECLARATION: {
            break;
        }
        case ir::AstNodeType::ETS_IMPORT_DECLARATION: {
            return BuildImportDeclaration(childNode->AsETSImportDeclaration());
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            return BuildMemberExpression(childNode->AsMemberExpression());
        }
        case ir::AstNodeType::METHOD_DEFINITION: {
            return BuildMethodDefinition(childNode->AsMethodDefinition());
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            return BuildETSNewClassInstanceExpression(childNode->AsETSNewClassInstanceExpression());
        }
        case ir::AstNodeType::ETS_FUNCTION_TYPE: {
            return BuildSignatureDeclarationBaseParams(childNode);
        }
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            return BuildObjectExpression(childNode->AsObjectExpression());
        }
        case ir::AstNodeType::ANNOTATION_USAGE: {
            return BuildAnnotationUsage(childNode->AsAnnotationUsage());
        }
        case ir::AstNodeType::ANNOTATION_DECLARATION: {
            BuildAnnotationDeclaration(childNode->AsAnnotationDeclaration());
            break;
        }
        default: {
            return ResolveReferences(childNode);
        }
    }
}

bool ETSBinder::BuildInternalName(ir::ScriptFunction *scriptFunc)
{
    const bool isExternal = recordTable_->IsExternal();
    if (isExternal) {
        scriptFunc->AddFlag(ir::ScriptFunctionFlags::EXTERNAL);
    }

    if (scriptFunc->IsArrow()) {
        return true;
    }

    auto *funcScope = scriptFunc->Scope();
    funcScope->BindName(recordTable_->RecordName());

    bool compilable = scriptFunc->Body() != nullptr && !isExternal;
    if (!compilable) {
        recordTable_->Signatures().push_back(funcScope);
    }

    return compilable;
}

bool ETSBinder::BuildInternalNameWithCustomRecordTable(ir::ScriptFunction *const scriptFunc,
                                                       RecordTable *const recordTable)
{
    const bool isExternal = recordTable->IsExternal();
    if (isExternal) {
        scriptFunc->AddFlag(ir::ScriptFunctionFlags::EXTERNAL);
    }

    if (scriptFunc->IsArrow()) {
        return true;
    }

    auto *const funcScope = scriptFunc->Scope();
    funcScope->BindName(recordTable->RecordName());

    const bool compilable = scriptFunc->Body() != nullptr && !isExternal;
    if (!compilable) {
        recordTable->Signatures().push_back(funcScope);
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
    auto *funcScope = func->Scope();

    std::stringstream ss;
    ES2PANDA_ASSERT(func->IsArrow() || !funcScope->Name().Empty());
    ss << (func->IsExternalOverload() ? funcScope->InternalName() : funcScope->Name())
       << compiler::Signatures::METHOD_SEPARATOR;

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

    signature->ToAssemblerType(ss);

    util::UString internalName(ss.str(), Allocator());
    funcScope->BindInternalName(internalName.View());
}

void ETSBinder::InitImplicitThisParam()
{
    thisParam_ = Allocator()->New<ir::Identifier>("this", Allocator());
}

void ETSBinder::BuildProgram()
{
    for (auto &[_, extPrograms] : Program()->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            BuildExternalProgram(extProg);
        }
    }

    for (auto *defaultImport : defaultImports_) {
        BuildImportDeclaration(defaultImport);
    }

    ValidateReexports();

    auto &stmts = Program()->Ast()->Statements();
    const auto etsGlobal = std::find_if(stmts.begin(), stmts.end(), [](const ir::Statement *stmt) {
        if (stmt->IsClassDeclaration() &&
            !stmt->AsClassDeclaration()->Definition()->Ident()->Name().Is(compiler::Signatures::ETS_GLOBAL)) {
            ES2PANDA_ASSERT(stmt->AsClassDeclaration()->Definition()->Ident()->Name().Utf8().find(
                                // CC-OFFNXT(G.FMT.06-CPP,G.FMT.05-CPP) project code style
                                compiler::Signatures::ETS_GLOBAL) == std::string::npos);
        }
        return stmt->IsClassDeclaration() &&
               stmt->AsClassDeclaration()->Definition()->Ident()->Name().Is(compiler::Signatures::ETS_GLOBAL);
    });
    if (etsGlobal != stmts.end()) {
        const auto begin = std::find_if(stmts.rbegin(), stmts.rend(), [](const ir::Statement *stmt) {
                               return stmt->IsETSImportDeclaration() || stmt->IsETSPackageDeclaration();
                           }).base();

        const auto index = std::distance(begin, etsGlobal);
        std::rotate(begin, begin + index, begin + index + 1);
    }

    for (auto *stmt : stmts) {
        ResolveReference(stmt);
    }
}

void ETSBinder::BuildExternalProgram(parser::Program *extProgram)
{
    auto *savedProgram = Program();
    auto *savedRecordTable = recordTable_;
    auto *savedTopScope = TopScope();

    auto flags = Program()->VarBinder()->IsGenStdLib() ? RecordTableFlags::NONE : RecordTableFlags::EXTERNAL;
    auto *extRecordTable = Allocator()->New<RecordTable>(Allocator(), extProgram, flags);
    externalRecordTable_.insert({extProgram, extRecordTable});

    ResetTopScope(extProgram->GlobalScope());
    recordTable_ = extRecordTable;
    SetProgram(extProgram);

    BuildProgram();

    SetProgram(savedProgram);
    recordTable_ = savedRecordTable;
    ResetTopScope(savedTopScope);
}

void ETSBinder::BuildETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *classInstance)
{
    ResolveReference(classInstance->GetTypeRef());

    for (auto *arg : classInstance->GetArguments()) {
        ResolveReference(arg);
    }
}

void ETSBinder::BuildImportDeclaration(ir::ETSImportDeclaration *decl)
{
    if (!decl->IsValid()) {
        return;
    }

    if (decl->Source()->Str() == Program()->SourceFile().GetAbsolutePath()) {
        return;
    }

    const auto &specifiers = decl->Specifiers();

    for (auto specifier : specifiers) {
        AddSpecifiersToTopBindings(specifier, decl);
    }
}

Variable *ETSBinder::ValidateImportSpecifier(const ir::ImportSpecifier *const specifier,
                                             const ir::ETSImportDeclaration *const import)
{
    const auto records = varbinder::GetExternalProgram(this, import);
    if (records.empty()) {
        return nullptr;
    }

    const auto *const importProgram = records.front();
    const auto *const importGlobalScope = importProgram->GlobalScope();
    const auto &globalBindings = importGlobalScope->Bindings();

    auto imported = specifier->Imported()->Name();
    for (const auto *const item : import->Specifiers()) {
        // Handle alias
        // export {foo as FOO}
        if (item->IsImportSpecifier() && item->AsImportSpecifier()->Local()->Name().Is(imported.Mutf8()) &&
            !item->AsImportSpecifier()->Local()->Name().Is(item->AsImportSpecifier()->Imported()->Name().Mutf8())) {
            imported = item->AsImportSpecifier()->Imported()->Name();
        }
    }

    auto *const var = FindImportSpecifiersVariable(imported, globalBindings, Span {records});
    if (var != nullptr) {
        return var;
    }

    // Failed to find variable, go through reexports
    const ir::ETSImportDeclaration *const implDecl = FindImportDeclInReExports(import, imported, import->Source());
    if (implDecl != nullptr) {
        return ValidateImportSpecifier(specifier, implDecl);
    }

    return nullptr;
}

void ETSBinder::ValidateReexports()
{
    // This will throw syntax error if the reexport is incorrect
    // This will also set variables and check for ambiguous reexports
    for (auto *reexport : reExportImports_) {
        ValidateReexportDeclaration(reexport);
    }

    reexportedNames_.clear();
}

void ETSBinder::ValidateReexportDeclaration(ir::ETSReExportDeclaration *decl)
{
    // Reexport declarations are available in all files, see ReExportImports()
    // Check that reexport declaration is in this file
    const auto program = Program()->SourceFile().GetAbsolutePath();
    const auto reexportSource = os::GetAbsolutePath(decl->GetProgramPath().Utf8());
    if (program.Utf8() != reexportSource) {
        return;
    }

    const auto *const import = decl->GetETSImportDeclarations();
    const auto &specifiers = import->Specifiers();
    for (auto specifier : specifiers) {
        // Example: export {foo} from "./A"
        if (specifier->IsImportSpecifier()) {
            auto importSpecifier = specifier->AsImportSpecifier();
            const auto reexported = importSpecifier->Imported()->Name();
            auto *const var = ValidateImportSpecifier(importSpecifier, import);
            if (var == nullptr) {
                ThrowError(import->Start(), "Incorrect export \"" + reexported.Mutf8() + "\"");
                continue;
            }

            importSpecifier->Imported()->SetVariable(var);
            importSpecifier->Local()->SetVariable(var);

            // Remember reexported name to check for ambiguous reexports
            if (!reexportedNames_.insert(reexported).second) {
                ThrowError(import->Start(), "Ambiguous export \"" + reexported.Mutf8() + "\"");
                continue;
            }
        }

        if (specifier->IsImportNamespaceSpecifier()) {
            // NOTE(kkonkuznetsov): See #20658
            // How to validate ambiguous exports with namespace specifiers?
            // Example:
            // export * from "./A"
            // export * from "./B"
        }
    }
}

bool ETSBinder::ImportGlobalPropertiesForNotDefaultedExports(varbinder::Variable *var, const util::StringView &name,
                                                             const ir::ClassElement *classElement)
{
    if (var->Declaration()->Node()->IsDefaultExported()) {
        return false;
    }

    auto variable = Program()->GlobalClassScope()->FindLocal(name, ResolveBindingOptions::ALL);

    bool isStdLib = util::Helpers::IsStdLib(Program());
    if (variable != nullptr && var != variable) {
        if (variable->Declaration()->IsFunctionDecl() && var->Declaration()->IsFunctionDecl()) {
            AddOverloadFlag(Allocator(), isStdLib, var, variable);
            return true;
        }

        ThrowError(classElement->Id()->Start(), RedeclarationErrorMessageAssembler(var, variable, name.Utf8()));
    }

    const auto insRes = TopScope()->InsertForeignBinding(name, var);
    if (!(!insRes.second && insRes.first != TopScope()->Bindings().end()) || !(insRes.first->second != var)) {
        return true;
    }
    if (insRes.first->second->Declaration()->IsFunctionDecl() && var->Declaration()->IsFunctionDecl()) {
        AddOverloadFlag(Allocator(), isStdLib, var, insRes.first->second);
        return true;
    }

    ThrowError(classElement->Id()->Start(), RedeclarationErrorMessageAssembler(var, insRes.first->second, name.Utf8()));
    return false;
}

void ETSBinder::ImportGlobalProperties(const ir::ClassDefinition *const classDef)
{
    const auto scopeCtx = LexicalScope<ClassScope>::Enter(this, classDef->Scope()->AsClassScope());

    for (const auto *const prop : classDef->Body()) {
        const auto *const classElement = prop->AsClassElement();

        if (classElement->IsClassStaticBlock()) {
            continue;
        }

        ES2PANDA_ASSERT(classElement->IsStatic());
        const auto &name = classElement->Id()->Name();
        auto *const var = scopeCtx.GetScope()->FindLocal(name, ResolveBindingOptions::ALL);
        ES2PANDA_ASSERT(var != nullptr);

        if (ImportGlobalPropertiesForNotDefaultedExports(var, name, classElement)) {
            return;
        }
    }
}

const DynamicImportData *ETSBinder::DynamicImportDataForVar(const Variable *var) const noexcept
{
    auto it = dynamicImportVars_.find(var);
    if (it == dynamicImportVars_.cend()) {
        return nullptr;
    }

    return &it->second;
}

ArenaVector<parser::Program *> ETSBinder::GetProgramList(const util::StringView &path) const noexcept
{
    auto const *globalProgram = globalRecordTable_.Program();

    for (const auto &extRecords : globalProgram->ExternalSources()) {
        for (const auto &program : extRecords.second) {
            if (program->AbsoluteName() == path) {
                return extRecords.second;
            }

            // in case of importing a package folder, the path could not be resolved to a specific file
            if (program->IsPackage() && program->SourceFileFolder() == path) {
                return extRecords.second;
            }
        }
    }

    if (globalProgram->IsPackage() && path.Compare(globalProgram->SourceFileFolder()) == 0) {
        return ArenaVector<parser::Program *>({GetContext()->parserProgram}, Allocator()->Adapter());
    }

    return ArenaVector<parser::Program *>(Allocator()->Adapter());
}

bool ETSBinder::IsDynamicModuleVariable(const Variable *var) const noexcept
{
    auto *data = DynamicImportDataForVar(var);
    if (data == nullptr) {
        return false;
    }

    return data->specifier->IsImportSpecifier();
}

bool ETSBinder::IsDynamicNamespaceVariable(const Variable *var) const noexcept
{
    auto *data = DynamicImportDataForVar(var);
    if (data == nullptr) {
        return false;
    }

    return data->specifier->IsImportNamespaceSpecifier();
}

void ETSBinder::ThrowError(const lexer::SourcePosition &pos, const std::string_view msg) const
{
    GetContext()->diagnosticEngine->LogSemanticError(msg, pos);
}

bool ETSBinder::IsGlobalIdentifier([[maybe_unused]] const util::StringView &str) const
{
    return false;
}

}  // namespace ark::es2panda::varbinder
