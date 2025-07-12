/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dynamicImport.h"
#include <algorithm>
#include <string>
#include "checker/ETSchecker.h"
#include "ir/astNode.h"

#include "compiler/lowering/util.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;
static constexpr std::string_view LAZY_IMPORT_OBJECT_SUFFIX = "%%lazyImportObject-";
static constexpr std::string_view FIELD_NAME = "value";

ir::ClassDeclaration *GetOrCreateLazyImportObjectClass(ark::ArenaAllocator *allocator,
                                                       ir::ETSImportDeclaration *importDecl, parser::Program *program)
{
    auto checker = program->Checker()->AsETSChecker();
    auto globalClass = program->GlobalClass();
    auto varbinder = checker->VarBinder()->AsETSBinder();
    auto sourceProgram = checker->SelectEntryOrExternalProgram(varbinder, importDecl->DeclPath());

    const std::string classNameStr = std::string(LAZY_IMPORT_OBJECT_SUFFIX) + sourceProgram->ModuleName().Mutf8();
    const util::UString className(classNameStr, allocator);
    const auto nameView = className.View().Mutf8();

    auto &classBody = globalClass->BodyForUpdate();
    auto classIt = std::find_if(classBody.begin(), classBody.end(), [&nameView](ir::AstNode *node) {
        if (!node->IsClassDeclaration()) {
            return false;
        }
        return node->AsClassDeclaration()->Definition()->Ident()->Name().Mutf8() == nameView;
    });
    if (classIt != classBody.end()) {
        return (*classIt)->AsClassDeclaration();
    }

    auto *ident = allocator->New<ir::Identifier>(className.View(), allocator);
    auto *classDef = util::NodeAllocator::ForceSetParent<ir::ClassDefinition>(
        allocator, allocator, ident, ir::ClassDefinitionModifiers::CLASS_DECL, ir::ModifierFlags::ABSTRACT,
        Language(Language::Id::ETS));

    classDef->SetLazyImportObjectClass();
    return util::NodeAllocator::ForceSetParent<ir::ClassDeclaration>(allocator, classDef, allocator);
}

static void AddImportInitializationStatement(public_lib::Context *ctx, ir::ETSImportDeclaration *import,
                                             ArenaVector<ir::Statement *> *statements, util::StringView className)
{
    auto allocator = ctx->GetChecker()->AsETSChecker()->ProgramAllocator();
    const auto builtin = compiler::Signatures::Dynamic::LoadModuleBuiltin(import->Language());
    auto [builtinClassName, builtinMethodName] = util::Helpers::SplitSignature(builtin);

    auto *classId = allocator->New<ir::Identifier>(builtinClassName, allocator);
    auto *methodId = allocator->New<ir::Identifier>(builtinMethodName, allocator);
    auto *callee = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    util::StringView ohmUrl = util::UString(import->OhmUrl(), allocator).View();
    if (ohmUrl.Empty()) {
        ohmUrl = import->ResolvedSource();
        if (ark::os::file::File::IsRegularFile(ohmUrl.Mutf8())) {
            ohmUrl = util::UString(ark::os::RemoveExtension(ohmUrl.Mutf8()), allocator).View();
        }
    }

    ArenaVector<ir::Expression *> callParams(allocator->Adapter());
    callParams.push_back(allocator->New<ir::StringLiteral>(ohmUrl));

    auto *loadCall = util::NodeAllocator::ForceSetParent<ir::CallExpression>(allocator, callee, std::move(callParams),
                                                                             nullptr, false);
    auto *moduleClassId = allocator->New<ir::Identifier>(className, allocator);
    auto *fieldId = allocator->New<ir::Identifier>(FIELD_NAME, allocator);
    auto *property = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, moduleClassId, fieldId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    moduleClassId->SetParent(property);
    fieldId->SetParent(property);

    auto *initializer = util::NodeAllocator::ForceSetParent<ir::AssignmentExpression>(
        allocator, property, loadCall, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    statements->push_back(util::NodeAllocator::ForceSetParent<ir::ExpressionStatement>(allocator, initializer));
}

checker::Type *CreateModuleObjectType(public_lib::Context *ctx, ir::ETSImportDeclaration *importDecl)
{
    auto checker = ctx->GetChecker()->AsETSChecker();
    auto varbinder = static_cast<varbinder::ETSBinder *>(checker->VarBinder()->AsETSBinder());
    auto allocator = checker->ProgramAllocator();

    const auto importPath = importDecl->DeclPath();
    auto program = checker->SelectEntryOrExternalProgram(varbinder, importPath);
    if (program == nullptr) {
        return checker->GlobalTypeError();
    }

    const auto moduleName = program->ModuleName();
    const auto internalNameStr = std::string(moduleName.Mutf8())
                                     .append(compiler::Signatures::METHOD_SEPARATOR)
                                     .append(compiler::Signatures::ETS_GLOBAL);
    const util::UString internalName(internalNameStr, allocator);

    auto *moduleObjectType = allocator->New<checker::ETSObjectType>(
        allocator, moduleName, internalName.View(),
        std::make_tuple(program->GlobalClass(), checker::ETSObjectFlags::CLASS, checker->Relation()));

    auto *rootDecl = allocator->New<varbinder::ClassDecl>(moduleName);
    auto *rootVar = allocator->New<varbinder::LocalVariable>(rootDecl, varbinder::VariableFlags::NONE);
    rootVar->SetTsType(moduleObjectType);
    checker->SetPropertiesForModuleObject(moduleObjectType, importPath, nullptr);

    return moduleObjectType;
}

static void BuildLazyImportObject(public_lib::Context *ctx, ir::ETSImportDeclaration *importDecl,
                                  parser::Program *program,
                                  ArenaUnorderedMap<util::StringView, checker::ETSObjectType *> &moduleMap,
                                  ArenaUnorderedMap<varbinder::Variable *, ir::ClassDefinition *> &varMap)
{
    auto checker = ctx->GetChecker()->AsETSChecker();
    auto varBinder = checker->VarBinder()->AsETSBinder();
    auto allocator = checker->ProgramAllocator();

    auto declProgram = checker->SelectEntryOrExternalProgram(varBinder, importDecl->DeclPath());
    if (!declProgram->IsDeclForDynamicStaticInterop()) {
        return;
    }

    auto *classDecl = GetOrCreateLazyImportObjectClass(allocator, importDecl, program);
    for (auto specifier : importDecl->Specifiers()) {
        auto var = specifier->AsImportSpecifier()->Imported()->Variable();
        var->AddFlag(varbinder::VariableFlags::DYNAMIC);
        varMap.insert({var, classDecl->Definition()});
    }

    const auto className = classDecl->Definition()->Ident()->Name();
    auto found = moduleMap.find(className);
    if (declProgram->IsASTChecked() && found != moduleMap.end()) {
        checker->SetPropertiesForModuleObject(found->second, importDecl->DeclPath(), nullptr);
        return;
    }

    auto *objType = CreateModuleObjectType(ctx, importDecl)->AsETSObjectType();
    moduleMap.insert({className, objType});

    objType->AddObjectFlag(checker::ETSObjectFlags::LAZY_IMPORT_OBJECT);
    auto moduleType = checker->CreateGradualType(objType, Language::Id::JS);

    auto parser = ctx->parser->AsETSParser();
    auto *typeAnnotation = allocator->New<ir::OpaqueTypeNode>(moduleType, allocator);
    auto *classProp = parser->CreateFormattedClassFieldDefinition(std::string {FIELD_NAME} + ": @@T1", typeAnnotation)
                          ->AsClassProperty();
    typeAnnotation->SetParent(classProp);
    classProp->AddModifier(ir::ModifierFlags::CONST | ir::ModifierFlags::STATIC);

    classDecl->Definition()->EmplaceBody(classProp);
    classProp->SetParent(classDecl->Definition());

    auto initializer = checker->CreateClassStaticInitializer(
        [ctx, importDecl, className](ArenaVector<ir::Statement *> *statements,
                                     [[maybe_unused]] ArenaVector<ir::Expression *> *params) {
            AddImportInitializationStatement(ctx, importDecl, statements, className);
        });

    classDecl->Definition()->EmplaceBody(initializer);
    initializer->SetParent(classDecl->Definition());

    for (auto specifier : importDecl->Specifiers()) {
        varMap.insert({specifier->AsImportSpecifier()->Imported()->Variable(), classDecl->Definition()});
    }

    program->GlobalClass()->EmplaceBody(classDecl);
    classDecl->SetParent(program->GlobalClass());

    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, program->GlobalClassScope());
    InitScopesPhaseETS::RunExternalNode(classDecl, varBinder);
    varBinder->ResolveReferencesForScopeWithContext(classDecl, varBinder->TopScope());
    classDecl->Check(checker);
}

static AstNodePtr TransformIdentifier(ir::Identifier *ident, public_lib::Context *ctx,
                                      const ArenaUnorderedMap<varbinder::Variable *, ir::ClassDefinition *> &varMap)
{
    auto checker = ctx->GetChecker()->AsETSChecker();
    auto varBinder = checker->VarBinder()->AsETSBinder();
    auto allocator = checker->ProgramAllocator();

    const auto parent = ident->Parent();
    if (parent->IsImportSpecifier() || parent->IsScriptFunction() || parent->IsMethodDefinition()) {
        return ident;
    }

    auto varIt = varMap.find(ident->Variable());
    if (varIt == varMap.end()) {
        return ident;
    }

    auto newIdent = allocator->New<ir::Identifier>(ident->Variable()->Name(), allocator);
    auto *leftId = allocator->New<ir::Identifier>(varIt->second->Ident()->Name(), allocator);
    auto *rightId = allocator->New<ir::Identifier>(FIELD_NAME, allocator);

    auto *expr = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, leftId, rightId, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    auto *memberExpr = util::NodeAllocator::ForceSetParent<ir::MemberExpression>(
        allocator, expr, newIdent, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    memberExpr->SetParent(parent);
    CheckLoweredNode(varBinder, checker, memberExpr);

    return memberExpr;
}

bool DynamicImport::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    auto allocator = ctx->GetChecker()->ProgramAllocator();
    ArenaUnorderedMap<varbinder::Variable *, ir::ClassDefinition *> varMap {allocator->Adapter()};
    ArenaUnorderedMap<util::StringView, checker::ETSObjectType *> moduleMap {allocator->Adapter()};

    auto dynamicImports = program->VarBinder()->AsETSBinder()->DynamicImports();
    for (auto *importDecl : dynamicImports) {
        BuildLazyImportObject(ctx, importDecl, program, moduleMap, varMap);
    }

    program->Ast()->TransformChildrenRecursively(
        [ctx, &varMap](ir::AstNode *node) -> AstNodePtr {
            if (node->IsIdentifier() && node->AsIdentifier()->Variable() != nullptr) {
                return TransformIdentifier(node->AsIdentifier(), ctx, varMap);
            }
            return node;
        },
        Name());

    return true;
}
}  // namespace ark::es2panda::compiler