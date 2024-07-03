/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_VARBINDER_ETSBINDER_H
#define ES2PANDA_VARBINDER_ETSBINDER_H

#include "varbinder/TypedBinder.h"
#include "varbinder/recordTable.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "ir/expressions/identifier.h"
#include "ir/module/importSpecifier.h"
#include "parser/program/program.h"
#include "util/importPathManager.h"

namespace ark::es2panda::varbinder {
using AliasesByExportedNames = ArenaMap<util::StringView, util::StringView>;
using ModulesToExportedNamesWithAliases = ArenaMap<util::StringView, AliasesByExportedNames>;

struct DynamicImportData {
    const ir::ETSImportDeclaration *import;
    const ir::AstNode *specifier;
    Variable *variable;
};

using DynamicImportVariables = ArenaUnorderedMap<const Variable *, DynamicImportData>;

class ETSBinder : public TypedBinder {
public:
    explicit ETSBinder(ArenaAllocator *allocator)
        : TypedBinder(allocator),
          globalRecordTable_(allocator, Program(), RecordTableFlags::NONE),
          recordTable_(&globalRecordTable_),
          externalRecordTable_(Allocator()->Adapter()),
          defaultImports_(Allocator()->Adapter()),
          dynamicImports_(Allocator()->Adapter()),
          reExportImports_(Allocator()->Adapter()),
          dynamicImportVars_(Allocator()->Adapter()),
          importSpecifiers_(Allocator()->Adapter()),
          selectiveExportAliasMultimap_(Allocator()->Adapter())
    {
        InitImplicitThisParam();
    }

    NO_COPY_SEMANTIC(ETSBinder);
    NO_MOVE_SEMANTIC(ETSBinder);
    ~ETSBinder() override = default;

    ScriptExtension Extension() const override
    {
        return ScriptExtension::ETS;
    }

    ResolveBindingOptions BindingOptions() const override
    {
        return ResolveBindingOptions::BINDINGS;
    }

    RecordTable *GetRecordTable()
    {
        return recordTable_;
    }

    const RecordTable *GetRecordTable() const
    {
        return recordTable_;
    }

    void SetRecordTable(RecordTable *table)
    {
        recordTable_ = table;
    }

    RecordTable *GetGlobalRecordTable()
    {
        return &globalRecordTable_;
    }

    const RecordTable *GetGlobalRecordTable() const
    {
        return &globalRecordTable_;
    }

    ArenaMap<parser::Program *, RecordTable *> &GetExternalRecordTable()
    {
        return externalRecordTable_;
    }

    const ArenaMap<parser::Program *, RecordTable *> &GetExternalRecordTable() const
    {
        return externalRecordTable_;
    }

    void HandleCustomNodes(ir::AstNode *childNode) override;

    void IdentifierAnalysis() override;
    void BuildClassDefinition(ir::ClassDefinition *classDef) override;
    void BuildClassProperty(const ir::ClassProperty *prop) override;
    void LookupIdentReference(ir::Identifier *ident) override;
    bool BuildInternalName(ir::ScriptFunction *scriptFunc) override;
    void AddCompilableFunction(ir::ScriptFunction *func) override;

    void LookupTypeReference(ir::Identifier *ident, bool allowDynamicNamespaces);
    void LookupTypeArgumentReferences(ir::ETSTypeReference *typeRef);
    void BuildInterfaceDeclaration(ir::TSInterfaceDeclaration *decl);
    void BuildMemberExpression(ir::MemberExpression *memberExpr);
    void BuildMethodDefinition(ir::MethodDefinition *methodDef);
    void BuildImportDeclaration(ir::ETSImportDeclaration *decl);
    void BuildETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *classInstance);
    bool DetectNameConflict(const util::StringView localName, Variable *const var, Variable *const otherVar,
                            const ir::StringLiteral *const importPath, bool overloadAllowed);
    void AddSpecifiersToTopBindings(ir::AstNode *specifier, const ir::ETSImportDeclaration *import);
    ArenaVector<parser::Program *> GetExternalProgram(const util::StringView &sourceName,
                                                      const ir::StringLiteral *importPath);
    bool AddImportNamespaceSpecifiersToTopBindings(ir::AstNode *specifier,
                                                   const varbinder::Scope::VariableMap &globalBindings,
                                                   const parser::Program *importProgram,
                                                   const varbinder::GlobalScope *importGlobalScope,
                                                   const ir::ETSImportDeclaration *import);
    ir::ETSImportDeclaration *FindImportDeclInReExports(const ir::ETSImportDeclaration *const import,
                                                        std::vector<ir::ETSImportDeclaration *> &viewedReExport,
                                                        const util::StringView &imported,
                                                        const ir::StringLiteral *const importPath);
    bool AddImportSpecifiersToTopBindings(ir::AstNode *specifier, const varbinder::Scope::VariableMap &globalBindings,
                                          const ir::ETSImportDeclaration *import,
                                          const ArenaVector<parser::Program *> &recordRes,
                                          std::vector<ir::ETSImportDeclaration *> viewedReExport);
    void ValidateImportVariable(varbinder::Variable *const var, const ir::ETSImportDeclaration *const import,
                                const util::StringView &imported, const ir::StringLiteral *const importPath);
    Variable *FindImportSpecifiersVariable(const util::StringView &imported,
                                           const varbinder::Scope::VariableMap &globalBindings,
                                           const ArenaVector<parser::Program *> &recordRes);
    Variable *FindStaticBinding(const ArenaVector<parser::Program *> &recordRes, const ir::StringLiteral *importPath);
    void AddSpecifiersToTopBindings(
        ir::AstNode *specifier, const ir::ETSImportDeclaration *import, ir::StringLiteral *path,
        std::vector<ir::ETSImportDeclaration *> viewedReExport = std::vector<ir::ETSImportDeclaration *>());
    void AddDynamicSpecifiersToTopBindings(ir::AstNode *specifier, const ir::ETSImportDeclaration *import);

    void ResolveInterfaceDeclaration(ir::TSInterfaceDeclaration *decl);
    void ResolveMethodDefinition(ir::MethodDefinition *methodDef);
    LocalScope *ResolvePropertyReference(ir::ClassProperty *prop, ClassScope *scope);
    void ResolveEnumDeclaration(ir::TSEnumDeclaration *enumDecl);
    void InitializeInterfaceIdent(ir::TSInterfaceDeclaration *decl);
    void BuildExternalProgram(parser::Program *extProgram);
    void BuildProgram();

    void BuildFunctionName(const ir::ScriptFunction *func) const;
    bool BuildInternalNameWithCustomRecordTable(ir::ScriptFunction *scriptFunc, RecordTable *recordTable);
    void BuildProxyMethod(ir::ScriptFunction *func, const util::StringView &containingClassName, bool isStatic,
                          bool isExternal);
    void AddFunctionThisParam(ir::ScriptFunction *func);

    void SetDefaultImports(ArenaVector<ir::ETSImportDeclaration *> defaultImports)
    {
        defaultImports_ = std::move(defaultImports);
    }

    void AddDynamicImport(ir::ETSImportDeclaration *import)
    {
        ASSERT(import->Language().IsDynamic());
        dynamicImports_.push_back(import);
    }

    const ArenaVector<ir::ETSImportDeclaration *> &DynamicImports() const
    {
        return dynamicImports_;
    }

    void AddReExportImport(ir::ETSReExportDeclaration *reExport)
    {
        reExportImports_.push_back(reExport);
    }

    const ArenaVector<ir::ETSReExportDeclaration *> &ReExportImports() const
    {
        return reExportImports_;
    }

    const DynamicImportVariables &DynamicImportVars() const
    {
        return dynamicImportVars_;
    }

    const ir::AstNode *DefaultExport()
    {
        return defaultExport_;
    }

    void SetDefaultExport(ir::AstNode *defaultExport)
    {
        defaultExport_ = defaultExport;
    }

    /* Returns the list of programs belonging to the same compilation unit based on a program path */
    ArenaVector<parser::Program *> GetProgramList(const util::StringView &path) const
    {
        for (const auto &extRecords : globalRecordTable_.Program()->ExternalSources()) {
            for (const auto &program : extRecords.second) {
                if (program->AbsoluteName() == path) {
                    return extRecords.second;
                }

                // in case of importing a package folder, the path could not be resolved to a specific file
                if (program->IsPackageModule() && program->SourceFileFolder() == path) {
                    return extRecords.second;
                }
            }
        }

        return ArenaVector<parser::Program *>(Allocator()->Adapter());
    }

    bool IsDynamicModuleVariable(const Variable *var) const;
    bool IsDynamicNamespaceVariable(const Variable *var) const;
    const DynamicImportData *DynamicImportDataForVar(const Variable *var) const;

    void ResolveReferenceForScope(ir::AstNode *node, Scope *scope);
    void ResolveReferencesForScope(ir::AstNode const *parent, Scope *scope);

    void ResolveReferencesForScopeWithContext(ir::AstNode *node, Scope *scope);

    bool CheckForRedeclarationError(const util::StringView &localName, Variable *const var,
                                    const ir::StringLiteral *const importPath);

    bool AddSelectiveExportAlias(util::StringView const &path, util::StringView const &key,
                                 util::StringView const &value)
    {
        if (auto foundMap = selectiveExportAliasMultimap_.find(path); foundMap != selectiveExportAliasMultimap_.end()) {
            return foundMap->second.insert({key, value}).second;
        }

        ArenaMap<util::StringView, util::StringView> map(Allocator()->Adapter());
        bool insertResult = map.insert({key, value}).second;
        selectiveExportAliasMultimap_.insert({path, map});
        return insertResult;
    }

    [[nodiscard]] const ModulesToExportedNamesWithAliases &GetSelectiveExportAliasMultimap() const noexcept
    {
        return selectiveExportAliasMultimap_;
    }

    util::StringView FindNameInAliasMap(const util::StringView &pathAsKey, const util::StringView &aliasName)
    {
        if (auto relatedMap = selectiveExportAliasMultimap_.find(pathAsKey);
            relatedMap != selectiveExportAliasMultimap_.end()) {
            if (auto item = relatedMap->second.find(aliasName); item != relatedMap->second.end()) {
                return item->second;
            }
        }

        return "";
    }

    util::StringView FindLocalNameForImport(const ir::ImportSpecifier *const importSpecifier,
                                            util::StringView &imported, const ir::StringLiteral *const importPath)
    {
        if (importSpecifier->Local() != nullptr) {
            auto checkImportPathAndName = [&importPath, &imported](const auto &savedSpecifier) {
                return importPath->Str() != savedSpecifier.first && imported == savedSpecifier.second;
            };
            if (!std::any_of(importSpecifiers_.begin(), importSpecifiers_.end(), checkImportPathAndName)) {
                TopScope()->EraseBinding(imported);
            }

            importSpecifiers_.emplace_back(importPath->Str(), imported);

            return importSpecifier->Local()->Name();
        }

        return imported;
    }

private:
    void BuildClassDefinitionImpl(ir::ClassDefinition *classDef);
    void InitImplicitThisParam();
    void HandleStarImport(ir::TSQualifiedName *importName, util::StringView fullPath);
    void ImportGlobalProperties(const ir::ClassDefinition *classDef);
    bool ImportGlobalPropertiesForNotDefaultedExports(varbinder::Variable *var, const util::StringView &name,
                                                      const ir::ClassElement *classElement);
    void InsertForeignBinding(ir::AstNode *specifier, const ir::ETSImportDeclaration *import,
                              const util::StringView &name, Variable *var);
    void ImportAllForeignBindings(ir::AstNode *specifier, const varbinder::Scope::VariableMap &globalBindings,
                                  const parser::Program *importProgram, const varbinder::GlobalScope *importGlobalScope,
                                  const ir::ETSImportDeclaration *import);

    RecordTable globalRecordTable_;
    RecordTable *recordTable_;
    ArenaMap<parser::Program *, RecordTable *> externalRecordTable_;
    ArenaVector<ir::ETSImportDeclaration *> defaultImports_;
    ArenaVector<ir::ETSImportDeclaration *> dynamicImports_;
    ArenaVector<ir::ETSReExportDeclaration *> reExportImports_;
    DynamicImportVariables dynamicImportVars_;
    ir::Identifier *thisParam_ {};
    ArenaVector<std::pair<util::StringView, util::StringView>> importSpecifiers_;
    ir::AstNode *defaultExport_ {};
    ModulesToExportedNamesWithAliases selectiveExportAliasMultimap_;

    friend class RecordTableContext;
};

class RecordTableContext {
public:
    RecordTableContext(ETSBinder *varBinder, parser::Program *extProgram)
        : varBinder_(varBinder), savedRecordTable_(varBinder->recordTable_)
    {
        varBinder->recordTable_ = varBinder->externalRecordTable_[extProgram];
    }

    NO_COPY_SEMANTIC(RecordTableContext);
    NO_MOVE_SEMANTIC(RecordTableContext);

    ~RecordTableContext()
    {
        varBinder_->recordTable_ = savedRecordTable_;
    }

private:
    ETSBinder *varBinder_;
    RecordTable *savedRecordTable_;
};

}  // namespace ark::es2panda::varbinder

#endif
