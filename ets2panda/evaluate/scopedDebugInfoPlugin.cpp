/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "evaluate/scopedDebugInfoPlugin.h"

#include "checker/ETSchecker.h"
#include "compiler/lowering/ets/topLevelStmts/globalClassHandler.h"
#include "compiler/lowering/phase.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"
#include "evaluate/classDeclarationCreator.h"
#include "evaluate/helpers.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "parser/ETSparser.h"
#include "parser/program/program.h"
#include "varbinder/ETSBinder.h"

#include "libpandafile/class_data_accessor-inl.h"

namespace ark::es2panda::evaluate {

static std::string GetVarDeclSourceCode(std::string_view varName, ScopedDebugInfoPlugin::RegisterNumber regNumber,
                                        const std::string &typeSignature, panda_file::Type::TypeId typeId,
                                        checker::GlobalTypesHolder *globalTypes)
{
    auto returnType = ToTypeName(typeSignature, globalTypes);
    ASSERT(returnType.has_value());
    std::stringstream sstream;
    sstream << "let " << varName << ':' << *returnType << '=' << DEBUGGER_API_CLASS_NAME << '.'
            << CreateGetterName(typeId) << '(' << regNumber << ')';
    // Must add cast from Object.
    if (typeId == panda_file::Type::TypeId::REFERENCE) {
        sstream << " as " << *returnType;
    }
    return sstream.str();
}

static std::string GetVarUpdateSourceCode(std::string_view varName, ScopedDebugInfoPlugin::RegisterNumber regNumber,
                                          panda_file::Type::TypeId typeId)
{
    std::stringstream sstream;
    sstream << DEBUGGER_API_CLASS_NAME << '.' << CreateSetterName(typeId) << '(' << regNumber << ',' << varName << ')';
    return sstream.str();
}

ScopedDebugInfoPlugin::ScopedDebugInfoPlugin(parser::Program *globalProgram, checker::ETSChecker *checker,
                                             const CompilerOptions &options)
    : checker_(checker),
      context_(options),
      debugInfoStorage_(options, checker->Allocator()),
      proxyProgramsMap_(checker->Allocator()),
      irChecker_(checker->Allocator()),
      classDeclCreator_(checker, irChecker_),
      prologueEpilogueMap_(checker->Allocator()->Adapter()),
      createdEntities_(checker->Allocator()->Adapter())
{
    ValidateEvaluationOptions(options);

    auto isContextValid = debugInfoStorage_.FillEvaluateContext(context_);
    if (!isContextValid) {
        LOG(FATAL, ES2PANDA) << "Can't create evaluate context" << std::endl;
    }

    CreateContextPrograms(globalProgram);
}

void ScopedDebugInfoPlugin::PreCheck()
{
    irChecker_.PreCheck(checker_);
}

void ScopedDebugInfoPlugin::PostCheck()
{
    ASSERT(prologueEpilogueMap_.empty());
}

void ScopedDebugInfoPlugin::AddPrologueEpilogue(ir::BlockStatement *block)
{
    auto iter = prologueEpilogueMap_.find(block);
    if (iter == prologueEpilogueMap_.end()) {
        return;
    }

    auto &statements = block->Statements();
    for (auto *stmt : iter->second.first) {
        statements.insert(statements.begin(), stmt);
    }
    for (auto *stmt : iter->second.second) {
        statements.emplace_back(stmt);
    }

    prologueEpilogueMap_.erase(iter);
}

varbinder::Variable *ScopedDebugInfoPlugin::FindIdentifier(ir::Identifier *ident)
{
    ASSERT(ident);

    SafeStateScope s(checker_);

    auto *var = FindLocalVariable(ident);
    if (var) {
        return var;
    }
    var = FindGlobalVariable(ident);
    if (var) {
        return var;
    }
    var = FindClass(ident);
    if (var) {
        return var;
    }
    return FindGlobalFunction(ident);
}

varbinder::Variable *ScopedDebugInfoPlugin::FindClass(ir::Identifier *ident)
{
    // The following algorithm is used:
    // - Search for `import * as B from "C"` statements.
    //   - If found, TODO
    //   - Else, proceed.
    // - Search classes which defined in the context file:
    //   - If found, recreate its structure and return.
    //   - Else, proceed.
    // - Search through the imported entities extracted from imports/exports table:
    //   - If the class was found, create parser::Program corresponding for the import source,
    //     where the class could be recreated.
    //   - Else, return nullptr.

    // TODO: support "import * as X".

    ASSERT(ident);

    auto *importerProgram = checker_->VarBinder()->Program();
    const auto &identName = ident->Name();
    LOG(DEBUG, ES2PANDA) << "ScopedDebugInfoPlugin: FindClass " << identName;

    // Search "import * as B" statements.
    // TODO: separate this into a method.
    auto importPath = debugInfoStorage_.FindNamedImportAll(context_.sourceFilePath.Utf8(), identName.Utf8());
    if (!importPath.empty()) {
        UNREACHABLE();
        return nullptr;
    }

    // Search in the context file.
    auto classId = debugInfoStorage_.FindClass(context_.sourceFilePath.Utf8(), identName.Utf8());
    if (classId.IsValid()) {
        return ImportGlobalEntity(context_.sourceFilePath, identName, importerProgram, identName,
                                  [classId](auto *self, auto *program, auto declSourcePath, auto declName) {
                                      return self->CreateIrClass(classId, program, declSourcePath, declName);
                                  });
    }

    // Search in imported entities.
    auto optFoundEntity = debugInfoStorage_.FindImportedEntity(context_.sourceFilePath.Utf8(), identName.Utf8());
    if (!optFoundEntity) {
        return nullptr;
    }

    const auto &[entitySourceFile, entitySourceName] = optFoundEntity.value();

    classId = debugInfoStorage_.FindClass(entitySourceFile, entitySourceName);
    if (!classId.IsValid()) {
        // The entity is not a class.
        return nullptr;
    }

    // Must pass the name of class as declared in the found file.
    return ImportGlobalEntity(entitySourceFile, entitySourceName, importerProgram, identName,
                              [classId](auto *self, auto *program, auto declSourcePath, auto declName) {
                                  return self->CreateIrClass(classId, program, declSourcePath, declName);
                              });
}

varbinder::Variable *ScopedDebugInfoPlugin::FindGlobalFunction(ir::Identifier *ident)
{
    // Correct overload resolution requires us to create all reachable functions with the given name,
    // so that Checker later could choose the correct one.
    ASSERT(ident);

    auto *allocator = Allocator();

    auto *importerProgram = checker_->VarBinder()->Program();
    auto identName = ident->Name();
    LOG(DEBUG, ES2PANDA) << "ScopedDebugInfoPlugin: FindGlobalFunction " << identName;

    ArenaVector<std::pair<parser::Program *, ArenaVector<ir::AstNode *>>> createdMethods(allocator->Adapter());

    // Build every global function from the context file.
    createdMethods.emplace_back(GetProgram(context_.sourceFilePath), ArenaVector<ir::AstNode *>(allocator->Adapter()));
    auto &fromContextFile = createdMethods.back().second;

    auto *var =
        ImportGlobalEntity(context_.sourceFilePath, identName, importerProgram, identName,
                           [&fromContextFile](auto *self, auto *program, auto declSourcePath, auto declName) {
                               return self->CreateIrGlobalMethods(fromContextFile, program, declSourcePath, declName);
                           });

    // Then search in imports.
    ArenaVector<EntityInfo> importedFunctions(allocator->Adapter());
    debugInfoStorage_.FindImportedFunctions(importedFunctions, context_.sourceFilePath.Utf8(), identName.Utf8());

    // Build all the found functions.
    for (const auto &[funcSourceFile, funcSourceName] : importedFunctions) {
        createdMethods.emplace_back(GetProgram(funcSourceFile), ArenaVector<ir::AstNode *>(allocator->Adapter()));
        auto &fromImported = createdMethods.back().second;

        auto *importedVar =
            ImportGlobalEntity(funcSourceFile, funcSourceName, importerProgram, identName,
                               [&fromImported](auto *self, auto *program, auto declSourcePath, auto declName) {
                                   return self->CreateIrGlobalMethods(fromImported, program, declSourcePath, declName);
                               });
        if (importedVar != nullptr) {
            ASSERT(var == nullptr || var == importedVar);
            var = importedVar;
        }
    }

    // Run Checker only after all functions are created, so that overloading could work correctly.
    for (auto &[program, methods] : createdMethods) {
        auto *globalClass = program->GlobalClass();
        auto *globalClassScope = program->GlobalClassScope();
        for (auto *method : methods) {
            irChecker_.CheckNewNode(checker_, method, globalClassScope, globalClass, program);
        }
    }

    return var;
}

varbinder::Variable *ScopedDebugInfoPlugin::FindGlobalVariable(ir::Identifier *ident)
{
    ASSERT(ident);

    auto *importerProgram = checker_->VarBinder()->Program();
    auto identName = ident->Name();
    LOG(DEBUG, ES2PANDA) << "ScopedDebugInfoPlugin: FindGlobalVariable " << identName;

    // Search in the context file.
    auto *var = ImportGlobalEntity(context_.sourceFilePath, identName, importerProgram, identName,
                                   &ScopedDebugInfoPlugin::CreateIrGlobalVariable);
    if (var != nullptr) {
        return var;
    }

    // Search within the imports.
    auto optFoundEntity = debugInfoStorage_.FindImportedEntity(context_.sourceFilePath.Utf8(), identName.Utf8());
    if (!optFoundEntity) {
        return nullptr;
    }

    const auto &[entitySourceFile, entitySourceName] = optFoundEntity.value();

    // Search once again, but in the exported source. Must pass the name of entity as declared in the found file.
    return ImportGlobalEntity(entitySourceFile, entitySourceName, importerProgram, identName,
                              &ScopedDebugInfoPlugin::CreateIrGlobalVariable);
}

varbinder::Variable *ScopedDebugInfoPlugin::FindLocalVariable(ir::Identifier *ident)
{
    // TODO: verify that function arguments are included.
    const auto &variables = context_.extractor->GetLocalVariableTable(context_.methodId);
    auto typedVarIter = variables.end();
    uint32_t startOffset = 0;

    const auto &identName = ident->Name();
    for (auto iter = variables.begin(); iter != variables.end(); ++iter) {
        const auto &varInfo = *iter;
        // std::cerr << "@@@@@@ " << varInfo.name << " [" << varInfo.startOffset << ", " << varInfo.endOffset << ')'
        //           << std::endl;
        // Must select the most nested variable for correct scope.
        if (identName.Is(varInfo.name) && varInfo.startOffset <= context_.bytecodeOffset &&
            context_.bytecodeOffset < varInfo.endOffset && startOffset <= varInfo.startOffset) {
            typedVarIter = iter;
            startOffset = varInfo.startOffset;
        }
    }
    if (typedVarIter != variables.end()) {
        // std::cerr << "@@@@@@@ " << typedVarIter->typeSignature << " vs " << typedVarIter->type << std::endl;
        return CreateVarDecl(ident, typedVarIter->regNumber, typedVarIter->typeSignature);
    }

    return nullptr;
}

void ScopedDebugInfoPlugin::ValidateEvaluationOptions(const CompilerOptions &options)
{
    if (!options.isEtsModule) {
        LOG(FATAL, ES2PANDA) << "Evaluation mode must be used in conjunction with ets-module option.";
    }
}

void ScopedDebugInfoPlugin::CreateContextPrograms(parser::Program *globalProgram)
{
    debugInfoStorage_.EnumerateContextFiles([this, globalProgram](auto sourceFilePath, auto, auto, auto moduleName) {
        CreateEmptyProgram(globalProgram, sourceFilePath, moduleName);
        return true;
    });
}

parser::Program *ScopedDebugInfoPlugin::CreateEmptyProgram(parser::Program *globalProgram,
                                                           std::string_view sourceFilePath, std::string_view moduleName)
{
    ASSERT(globalProgram);
    auto *allocator = Allocator();

    parser::Program *program = allocator->New<parser::Program>(allocator, globalProgram->VarBinder());
    program->SetSource({sourceFilePath, sourceFilePath, globalProgram->SourceFileFolder().Utf8(), false});
    program->SetModuleInfo(moduleName, false, moduleName.empty());
    auto *etsScript =
        allocator->New<ir::ETSScript>(allocator, ArenaVector<ir::Statement *>(allocator->Adapter()), program);
    program->SetAst(etsScript);

    AddExternalProgram(globalProgram, program, moduleName);
    proxyProgramsMap_.AddProgram(program);

    return program;
}

parser::Program *ScopedDebugInfoPlugin::GetProgram(util::StringView fileName)
{
    auto *program = proxyProgramsMap_.GetProgram(fileName);
    ASSERT(program);
    return program;
}

varbinder::Variable *ScopedDebugInfoPlugin::CreateIrGlobalMethods(ArenaVector<ir::AstNode *> &createdMethods,
                                                                  parser::Program *program,
                                                                  util::StringView pathToSource,
                                                                  util::StringView methodDeclName)
{
    varbinder::Variable *var = nullptr;

    auto *cda = debugInfoStorage_.GetGlobalClassAccessor(pathToSource.Utf8());
    cda->EnumerateMethods([this, &var, &createdMethods, program, methodDeclName](panda_file::MethodDataAccessor &mda) {
        if (!methodDeclName.Is(mda.GetFullName())) {
            return;
        }

        auto *method = classDeclCreator_.CreateClassMethod(mda);
        method->SetParent(program->GlobalClass());
        createdMethods.emplace_back(method);

        // Postpone Checker until the whole overload set is created.
        CheckGlobalEntity(program, method, false);

        // Sanity checks.
        auto *methodVar = method->AsClassElement()->Value()->AsFunctionExpression()->Function()->Id()->Variable();
        ASSERT(methodVar != nullptr);
        ASSERT(var == nullptr || var == methodVar);
        var = methodVar;
    });

    return var;
}

varbinder::Variable *ScopedDebugInfoPlugin::CreateIrGlobalVariable(parser::Program *program,
                                                                   util::StringView pathToSource,
                                                                   util::StringView varDeclName)
{
    const auto *pf = debugInfoStorage_.GetPandaFile(pathToSource.Utf8());
    ASSERT(pf);
    varbinder::Variable *var = nullptr;

    auto *cda = debugInfoStorage_.GetGlobalClassAccessor(pathToSource.Utf8());
    cda->EnumerateFields([this, program, varDeclName, pf, &var](panda_file::FieldDataAccessor &fda) {
        // All ETSGLOBAL fields must be static.
        ASSERT(fda.IsStatic());

        const char *name = utf::Mutf8AsCString(pf->GetStringData(fda.GetNameId()).data);
        if (!varDeclName.Is(name)) {
            return;
        }
        // Must be unique within global variables.
        ASSERT(var == nullptr);

        auto *typeNode = PandaTypeToTypeNode(*pf, fda, checker_);
        ASSERT(typeNode);

        // Global variable is found - add it into source module's global class properties.
        // TODO: ensure that everything is declared as public.
        auto modFlags = GetModifierFlags(fda) | ir::ModifierFlags::EXPORT;
        auto *field = classDeclCreator_.CreateClassProperty(name, typeNode, modFlags);
        // Fields parent will be set in `AddProperties`.
        program->GlobalClass()->AddProperties(ArenaVector<ir::AstNode *>(1, field, Allocator()->Adapter()));

        CheckGlobalEntity(program, field);
        var = field->Key()->AsIdentifier()->Variable();
    });

    return var;
}

varbinder::Variable *ScopedDebugInfoPlugin::CreateIrClass(panda_file::File::EntityId classId, parser::Program *program,
                                                          util::StringView pathToSource, util::StringView classDeclName)
{
    const auto *pf = debugInfoStorage_.GetPandaFile(pathToSource.Utf8());
    ASSERT(pf);
    // TODO: may cache the created `ClassDataAccessor`.
    auto cda = panda_file::ClassDataAccessor(*pf, classId);
    // Checker will be called directly in creator.
    const auto *classDecl = classDeclCreator_.CreateClassDeclaration(classDeclName, cda, program);
    return classDecl->Definition()->Ident()->Variable();
}

ir::ETSImportDeclaration *ScopedDebugInfoPlugin::CreateIrImport(util::StringView pathToDeclSourceFile,
                                                                util::StringView classDeclName,
                                                                util::StringView classImportedName)
{
    auto *binder = checker_->VarBinder()->AsETSBinder();
    auto *allocator = Allocator();

    auto *resolvedSource = checker_->AllocNode<ir::StringLiteral>(pathToDeclSourceFile);
    auto *source = checker_->AllocNode<ir::StringLiteral>(debugInfoStorage_.GetModuleName(pathToDeclSourceFile.Utf8()));
    auto *importSource =
        allocator->New<ir::ImportSource>(source, resolvedSource, ToLanguage(binder->Extension()), true);

    auto *local = checker_->AllocNode<ir::Identifier>(classDeclName, allocator);
    auto *imported = checker_->AllocNode<ir::Identifier>(classImportedName, allocator);
    auto *spec = checker_->AllocNode<ir::ImportSpecifier>(imported, local);
    ArenaVector<ir::AstNode *> specifiers(1, spec, allocator->Adapter());

    return checker_->AllocNode<ir::ETSImportDeclaration>(importSource, specifiers);
}

ArenaAllocator *ScopedDebugInfoPlugin::Allocator()
{
    return checker_->Allocator();
}

ArenaUnorderedMap<util::StringView, varbinder::Variable *> &ScopedDebugInfoPlugin::GetOrCreateEntitiesMap(
    parser::Program *program)
{
    ASSERT(program);
    auto iter = createdEntities_.find(program);
    if (iter == createdEntities_.end()) {
        return createdEntities_
            .emplace(program, ArenaUnorderedMap<util::StringView, varbinder::Variable *>(Allocator()->Adapter()))
            .first->second;
    }
    return iter->second;
}

void ScopedDebugInfoPlugin::InsertImportStatement(ir::Statement *importStatement, parser::Program *importerProgram)
{
    auto *topStatement = importerProgram->Ast();
    importStatement->SetParent(topStatement);
    // Can't insert right away until block's statements iteration ends.
    RegisterPrologueEpilogue<true>(topStatement, importStatement);

    CheckGlobalEntity(importerProgram, importStatement);
}

varbinder::Variable *ScopedDebugInfoPlugin::CreateVarDecl(ir::Identifier *ident, RegisterNumber regNumber,
                                                          const std::string &typeSignature)
{
    auto *binder = checker_->VarBinder();
    auto identName = ident->Name().Utf8();
    LOG(DEBUG, ES2PANDA) << "ScopedDebugInfoPlugin: CreateVarDecl " << identName << ", type " << typeSignature;

    auto typeId = GetTypeId(typeSignature);
    auto varDeclSource =
        GetVarDeclSourceCode(identName, regNumber, typeSignature, typeId, checker_->GetGlobalTypesHolder());

    // Set up correct scope before parsing statements.
    auto *topStatement = GetEnclosingBlock(ident);
    checker::ScopeContext ctx(checker_, topStatement->Scope());
    auto statementScope = varbinder::LexicalScope<varbinder::Scope>::Enter(binder, topStatement->Scope());

    parser::Program p(Allocator(), binder);
    auto parser =
        parser::ETSParser(&p, binder->GetContext()->config->options->CompilerOptions(), parser::ParserStatus::NO_OPTS);

    auto *varDecl = parser.CreateFormattedStatement(varDeclSource, parser::ParserContext::DEFAULT_SOURCE_FILE);
    ASSERT(varDecl != nullptr);
    varDecl->SetParent(topStatement);
    // Declaration will be placed at start of current scope.
    // Can't insert right away until block's statements iteration ends.
    RegisterPrologueEpilogue<true>(topStatement, varDecl);
    CheckLocalEntity(varDecl);

    // Yet don't track whether the value was modified, so store result unconditionally in the end of the scope.
    auto varUpdateSource = GetVarUpdateSourceCode(identName, regNumber, typeId);

    auto *varUpdate = parser.CreateFormattedStatement(varUpdateSource, parser::ParserContext::DEFAULT_SOURCE_FILE);
    ASSERT(varUpdate != nullptr);
    varUpdate->SetParent(topStatement);
    // Can't insert right away until block's statements iteration ends.
    RegisterPrologueEpilogue<false>(topStatement, varUpdate);
    CheckLocalEntity(varUpdate);

    // Local variables are not registered, as they can be found in local scope.
    ASSERT(varDecl->AsVariableDeclaration()->Declarators().size() == 1);
    return varDecl->AsVariableDeclaration()->Declarators()[0]->Id()->Variable();
}

void ScopedDebugInfoPlugin::CheckGlobalEntity(parser::Program *program, ir::AstNode *node, bool mustCheck)
{
    auto *globalClass = program->GlobalClass();
    auto *globalClassScope = program->GlobalClassScope();

    DoScopedAction(checker_, program, globalClassScope, globalClass, [this, globalClassScope, node]() {
        auto *binder = checker_->VarBinder()->AsETSBinder();
        compiler::InitScopesPhaseETS::RunExternalNode(node, binder);
        binder->ResolveReferencesForScope(node, globalClassScope);
    });
    if (mustCheck) {
        irChecker_.CheckNewNode(checker_, node, globalClassScope, globalClass, program);
    }
}

void ScopedDebugInfoPlugin::CheckLocalEntity(ir::AstNode *node)
{
    compiler::InitScopesPhaseETS::RunExternalNode(node, checker_->VarBinder());
    irChecker_.CheckNewNode(checker_, node, nullptr, nullptr, nullptr);
}

}  // namespace ark::es2panda::evaluate
