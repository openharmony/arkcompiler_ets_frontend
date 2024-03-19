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
#include "util/importPathManager.h"

namespace ark::es2panda::varbinder {

using ComputedLambdaObjects = ArenaMap<const ir::AstNode *, std::pair<ir::ClassDefinition *, checker::Signature *>>;

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
          lambdaObjects_(Allocator()->Adapter()),
          dynamicImportVars_(Allocator()->Adapter()),
          importSpecifiers_(Allocator()->Adapter()),
          moduleList_(Allocator()->Adapter())
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

    const ComputedLambdaObjects &LambdaObjects() const
    {
        return lambdaObjects_;
    }

    ComputedLambdaObjects &LambdaObjects()
    {
        return lambdaObjects_;
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
    void BuildFunctionType(ir::ETSFunctionType *funcType);
    void BuildProxyMethod(ir::ScriptFunction *func, const util::StringView &containingClassName, bool isStatic,
                          bool isExternal);
    void BuildLambdaObject(ir::AstNode *refNode, ir::ClassDefinition *lambdaObject, checker::Signature *signature,
                           bool isExternal);
    void AddLambdaFunctionThisParam(const ir::ScriptFunction *func, bool isExternal);
    void AddInvokeFunctionThisParam(ir::ScriptFunction *func);
    void BuildLambdaObjectName(const ir::AstNode *refNode);
    void FormLambdaName(util::UString &name, const util::StringView &signature);

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

    void SetModuleList(const ArenaMap<util::StringView, util::ImportPathManager::ModuleInfo> &moduleList)
    {
        moduleList_ = moduleList;
    }

    util::ImportPathManager::ModuleInfo GetModuleInfo(const util::StringView &path) const
    {
        auto it = moduleList_.find(path);

        ASSERT(it != moduleList_.end());

        return it->second;
    }

    bool IsDynamicModuleVariable(const Variable *var) const;
    bool IsDynamicNamespaceVariable(const Variable *var) const;
    const DynamicImportData *DynamicImportDataForVar(const Variable *var) const;

    void ResolveReferenceForScope(ir::AstNode *node, Scope *scope);
    void ResolveReferencesForScope(ir::AstNode const *parent, Scope *scope);

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
    ComputedLambdaObjects lambdaObjects_;
    DynamicImportVariables dynamicImportVars_;
    ir::Identifier *thisParam_ {};
    ArenaVector<std::pair<util::StringView, util::StringView>> importSpecifiers_;
    ArenaMap<util::StringView, util::ImportPathManager::ModuleInfo> moduleList_;
    ir::AstNode *defaultExport_ {};
};

}  // namespace ark::es2panda::varbinder

#endif
