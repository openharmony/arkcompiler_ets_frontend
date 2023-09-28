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

#ifndef ES2PANDA_BINDER_ETS_BINDER_H
#define ES2PANDA_BINDER_ETS_BINDER_H

#include "plugins/ecmascript/es2panda/binder/TypedBinder.h"
#include "plugins/ecmascript/es2panda/binder/recordTable.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsImportDeclaration.h"

namespace panda::es2panda::binder {

using ComputedLambdaObjects =
    ArenaUnorderedMap<const ir::AstNode *, std::pair<ir::ClassDefinition *, checker::Signature *>>;

class ETSBinder : public TypedBinder {
public:
    explicit ETSBinder(ArenaAllocator *allocator)
        : TypedBinder(allocator),
          global_record_table_(allocator, Program(), RecordTableFlags::NONE),
          record_table_(&global_record_table_),
          external_record_table_(Allocator()->Adapter()),
          default_imports_(Allocator()->Adapter()),
          dynamic_imports_(Allocator()->Adapter()),
          lambda_objects_(Allocator()->Adapter()),
          dynamic_import_vars_(Allocator()->Adapter()),
          import_specifiers_(Allocator()->Adapter())
    {
        InitImplicitThisParam();
    }

    NO_COPY_SEMANTIC(ETSBinder);
    NO_MOVE_SEMANTIC(ETSBinder);
    ~ETSBinder() = default;

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
        return record_table_;
    }

    const RecordTable *GetRecordTable() const
    {
        return record_table_;
    }

    RecordTable *GetGlobalRecordTable()
    {
        return &global_record_table_;
    }

    const RecordTable *GetGlobalRecordTable() const
    {
        return &global_record_table_;
    }

    ArenaUnorderedMap<parser::Program *, RecordTable *> &GetExternalRecordTable()
    {
        return external_record_table_;
    }

    const ArenaUnorderedMap<parser::Program *, RecordTable *> &GetExternalRecordTable() const
    {
        return external_record_table_;
    }

    const ComputedLambdaObjects &LambdaObjects() const
    {
        return lambda_objects_;
    }

    ComputedLambdaObjects &LambdaObjects()
    {
        return lambda_objects_;
    }

    void HandleCustomNodes(ir::AstNode *child_node) override;

    void IdentifierAnalysis() override;
    void BuildClassDefinition(ir::ClassDefinition *class_def) override;
    void BuildClassProperty(const ir::ClassProperty *prop) override;
    void LookupIdentReference(ir::Identifier *ident) override;
    bool BuildInternalName(ir::ScriptFunction *script_func) override;
    void AddCompilableFunction(ir::ScriptFunction *func) override;

    void LookupTypeReference(ir::Identifier *ident, bool allow_dynamic_namespaces);
    void LookupTypeArgumentReferences(ir::ETSTypeReference *type_ref);
    void BuildInterfaceDeclaration(ir::TSInterfaceDeclaration *decl);
    void BuildMemberExpression(ir::MemberExpression *member_expr);
    void BuildMethodDefinition(ir::MethodDefinition *method_def);
    void BuildImportDeclaration(ir::ETSImportDeclaration *decl);
    void BuildETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *class_instance);
    void BuildMethodReferenceExpression(ir::ETSMethodReferenceExpression *method_ref);
    void AddSpecifiersToTopBindings(ir::AstNode *specifier, const ir::ETSImportDeclaration *import);
    void AddDynamicSpecifiersToTopBindings(ir::AstNode *specifier);

    void ResolveInterfaceDeclaration(ir::TSInterfaceDeclaration *decl);
    void ResolveMethodDefinition(ir::MethodDefinition *method_def);
    LocalScope *ResolvePropertyReference(ir::ClassProperty *prop, ClassScope *scope);
    void ResolveEnumDeclaration(ir::TSEnumDeclaration *enum_decl);
    void InitializeInterfaceIdent(ir::TSInterfaceDeclaration *decl);
    void BuildExternalProgram(parser::Program *ext_program);
    void BuildProgram();

    void BuildFunctionName(const ir::ScriptFunction *func) const;
    void BuildFunctionType(ir::ETSFunctionType *func_type);
    void BuildProxyMethod(ir::ScriptFunction *func, const util::StringView &containing_class_name, bool is_static);
    void BuildLambdaObject(ir::AstNode *ref_node, ir::ClassDefinition *lambda_object, checker::Signature *signature);
    void AddLambdaFunctionThisParam(ir::ScriptFunction *func);
    void AddInvokeFunctionThisParam(ir::ScriptFunction *func);
    void BuildLambdaObjectName(const ir::AstNode *ref_node);
    void FormLambdaName(util::UString &name, const util::StringView &signature);
    void FormFunctionalInterfaceName(util::UString &name, const util::StringView &signature);
    void BuildFunctionalInterfaceName(ir::ETSFunctionType *func_type);

    void SetDefaultImports(ArenaVector<ir::ETSImportDeclaration *> default_imports)
    {
        default_imports_ = std::move(default_imports);
    }

    void AddDynamicImport(ir::ETSImportDeclaration *import)
    {
        ASSERT(import->IsPureDynamic());
        dynamic_imports_.push_back(import);
    }

    const ArenaVector<ir::ETSImportDeclaration *> &DynamicImports() const
    {
        return dynamic_imports_;
    }

    const ArenaVector<Variable *> &DynamicImportVars() const
    {
        return dynamic_import_vars_;
    }

    const ir::AstNode *DefaultExport()
    {
        return default_export_;
    }

    void SetDefaultExport(ir::AstNode *default_export)
    {
        default_export_ = default_export;
    }

    static constexpr std::string_view DEFAULT_IMPORT_SOURCE_FILE = "<default_import>.ets";
    static constexpr std::string_view DEFAULT_IMPORT_SOURCE = R"(
import * from "std/core";
import * from "std/math";
import * from "std/containers";
import * from "std/time";
import * from "std/interop/js";
import * from "escompat";
)";

private:
    void BuildClassDefinitionImpl(ir::ClassDefinition *class_def);
    void InitImplicitThisParam();
    void HandleStarImport(ir::TSQualifiedName *import_name, util::StringView full_path);
    void ImportGlobalProperties(const ir::ClassDefinition *class_def);

    RecordTable global_record_table_;
    RecordTable *record_table_;
    ArenaUnorderedMap<parser::Program *, RecordTable *> external_record_table_;
    ArenaVector<ir::ETSImportDeclaration *> default_imports_;
    ArenaVector<ir::ETSImportDeclaration *> dynamic_imports_;
    ComputedLambdaObjects lambda_objects_;
    ArenaVector<Variable *> dynamic_import_vars_;
    ir::Identifier *this_param_ {};
    ArenaVector<std::pair<util::StringView, util::StringView>> import_specifiers_;
    ir::AstNode *default_export_ {};
};

}  // namespace panda::es2panda::binder

#endif
