/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PARSER_TRANSFORMER_TRANSFORMER_H
#define ES2PANDA_PARSER_TRANSFORMER_TRANSFORMER_H

#include <macros.h>

#include "binder/binder.h"
#include "binder/scope.h"
#include "ir/astNode.h"
#include "parser/module/sourceTextModuleRecord.h"
#include "parser/parserFlags.h"
#include "parser/program/program.h"

namespace panda::es2panda::parser {

struct TsModuleInfo {
    util::StringView name;
    binder::Scope *scope;
};

using PrivatePropertyMap = std::unordered_map<util::StringView, util::StringView>;
using ComputedPropertyMap = std::unordered_map<ir::Statement *, util::StringView>;

struct ClassInfo {
    util::StringView name;
    size_t propertyIndex;
    PrivatePropertyMap *bindNameMap;
    ComputedPropertyMap *computedPropertyMap;
};

class DuringClass {
public:
    explicit DuringClass(ArenaVector<ClassInfo> *classList, util::StringView name)
    {
        classList_ = classList;
        classList_->push_back({name, 0, &bindNameMap_, &computedPropertyMap_});
    }

    ~DuringClass()
    {
        classList_->pop_back();
    }

private:
    PrivatePropertyMap bindNameMap_ {};
    ComputedPropertyMap computedPropertyMap_ {};
    ArenaVector<ClassInfo> *classList_ {nullptr};
};

class Transformer {
public:
    explicit Transformer(panda::ArenaAllocator *allocator)
        : program_(nullptr),
          tsModuleList_(allocator->Adapter()),
          classList_(allocator->Adapter())
    {
    }
    NO_COPY_SEMANTIC(Transformer);
    ~Transformer() = default;

    void Transform(Program *program);

private:
    static constexpr std::string_view PRIVATE_PROPERTY_SIGN = "#";
    static constexpr std::string_view NEW_VAR_PREFIX = "##";
    static constexpr std::string_view NEW_VAR_HEAD = "var_";
    static constexpr std::string_view INDEX_DIVISION = "_";
    static constexpr std::string_view CONSTRUCTOR_NAME = "undefined";
    static constexpr std::string_view CLASS_PROTOTYPE = "prototype";
    static constexpr std::string_view OBJECT_VAR_NAME = "Object";
    static constexpr std::string_view FUNC_NAME_OF_DEFINE_PROPERTY = "defineProperty";
    static constexpr std::string_view FUNC_NAME_OF_GET_OWN_PROPERTY_DESCRIPTOR = "getOwnPropertyDescriptor";

    void TransformFromTS();

    void AddVariableToNearestStatements(util::StringView name);
    void PushVariablesToNearestStatements(ir::BlockStatement *ast);

    ir::AstNode *VisitTSNodes(ir::AstNode *parent);
    ir::UpdateNodes VisitTSNode(ir::AstNode *childNode);
    ir::UpdateNodes VisitTsModuleDeclaration(ir::TSModuleDeclaration *childNode, bool isExport = false);
    std::vector<ir::AstNode *> VisitExportNamedVariable(ir::Statement *decl);
    ir::AstNode *VisitTsImportEqualsDeclaration(ir::TSImportEqualsDeclaration *node);
    ir::UpdateNodes VisitClassDeclaration(ir::ClassDeclaration *node);
    ir::UpdateNodes VisitClassExpression(ir::ClassExpression *node);
    void VisitTSParameterProperty(ir::ClassDefinition *node);
    std::vector<ir::ExpressionStatement *> VisitStaticProperty(ir::ClassDefinition *node, util::StringView name);
    void VisitPrivateProperty(ir::ClassDefinition *node);
    void VisitComputedProperty(ir::ClassDefinition *node);

    ir::VariableDeclaration *CreateVariableDeclarationWithIdentify(util::StringView name,
                                                                   VariableParsingFlags flags,
                                                                   ir::AstNode *node,
                                                                   bool isExport,
                                                                   ir::Expression *init = nullptr,
                                                                   bool needBinding = true);
    ir::CallExpression *CreateCallExpressionForTsModule(ir::TSModuleDeclaration *node,
                                                        util::StringView paramName,
                                                        bool isExport = false);
    ir::Expression *CreateTsModuleParam(util::StringView paramName, bool isExport);
    ir::ExpressionStatement *CreateTsModuleAssignment(util::StringView name);
    ir::Expression *CreateMemberExpressionFromQualified(ir::Expression *node);
    std::vector<ir::AstNode *> CreateClassDecorators(ir::ClassDeclaration *node);
    std::vector<ir::AstNode *> CreateMethodDecorators(util::StringView className,
                                                      ir::MethodDefinition *node,
                                                      bool isStatic);
    std::vector<ir::AstNode *> CreatePropertyDecorators(util::StringView className,
                                                        ir::ClassProperty *node,
                                                        bool isStatic);
    ir::CallExpression *CreateGetOwnPropertyDescriptorCall(ir::Expression *target, ir::Expression *key);
    ir::CallExpression *CreateDefinePropertyCall(ir::Expression *target, ir::Expression *key, ir::Expression *value);
    std::vector<ir::AstNode *> CreateParamDecorators(util::StringView className,
                                                     ir::MethodDefinition *node,
                                                     bool isConstructor,
                                                     bool isStatic);
    ir::MemberExpression *CreateClassPrototype(util::StringView className);
    ir::Expression *CreateDecoratorTarget(util::StringView className, bool isStatic);
    ir::Identifier *CreateReferenceIdentifier(util::StringView name);
    util::StringView CreatePrivatePropertyBindName(util::StringView name);
    util::StringView CreateNewVariable(bool needAddToStatements = true);
    util::StringView CreateNewVariableName() const;
    util::StringView CreateUniqueName(const std::string &head, size_t *index = nullptr) const;

    util::StringView GetNameFromModuleDeclaration(ir::TSModuleDeclaration *node) const;
    util::StringView GetParamName(ir::TSModuleDeclaration *node, util::StringView name) const;
    ir::Expression *GetClassMemberName(ir::Expression *key, bool isComputed, ir::Statement *node);
    binder::Scope *FindExportVariableInTsModuleScope(util::StringView name) const;
    binder::Variable *FindTSModuleVariable(const ir::Expression *node, binder::Scope *scope) const;
    util::StringView FindPrivatePropertyBindName(util::StringView name);
    void AddExportLocalEntryItem(util::StringView name, const ir::Identifier *identifier);
    bool IsInstantiatedTSModule(const ir::Expression *node) const;
    void SetOriginalNode(ir::UpdateNodes res, ir::AstNode *originalNode) const;

    bool IsTsModule() const
    {
        return (tsModuleList_.size() != 0);
    }

    template <typename T, typename... Args>
    T *AllocNode(Args &&... args)
    {
        auto ret = program_->Allocator()->New<T>(std::forward<Args>(args)...);
        if (ret == nullptr) {
            throw Error(ErrorType::GENERIC, "Unsuccessful allocation during parsing");
        }
        return ret;
    }

    ArenaAllocator *Allocator() const
    {
        return program_->Allocator();
    }

    binder::Binder *Binder() const
    {
        return program_->Binder();
    }

    binder::Scope *Scope() const
    {
        return Binder()->GetScope();
    }

    util::StringView GetCurrentTSModuleName() const
    {
        return tsModuleList_.back().name;
    }

    util::StringView FindTSModuleNameByScope(binder::Scope *scope) const
    {
        for (auto it : tsModuleList_) {
            if (it.scope == scope) {
                return it.name;
            }
        }
        UNREACHABLE();
    }

    ScriptExtension Extension() const
    {
        return program_->Extension();
    }

    SourceTextModuleRecord *GetSourceTextModuleRecord()
    {
        return program_->ModuleRecord();
    }

    util::StringView RecordName() const
    {
        return program_->RecordName();
    }

    size_t GetCurrentClassInfoPropertyIndex() const
    {
        return classList_.back().propertyIndex;
    }

    void SetCurrentClassInfoPropertyIndex(size_t newIndex)
    {
        classList_.back().propertyIndex = newIndex;
    }

    void AddPrivatePropertyBinding(util::StringView name, util::StringView bindName)
    {
        classList_.back().bindNameMap->insert({name, bindName});
    }

    void AddComputedPropertyBinding(ir::Statement *property, util::StringView name)
    {
        classList_.back().computedPropertyMap->insert({property, name});
    }

    util::StringView GetComputedPropertyBinding(ir::Statement *property)
    {
        auto classInfo = classList_.back();
        auto res = classInfo.computedPropertyMap->find(property);
        ASSERT(res != classInfo.computedPropertyMap->end());
        return res->second;
    }

    Program *program_;
    ArenaVector<TsModuleInfo> tsModuleList_;
    ArenaVector<ClassInfo> classList_;
    std::unordered_map<util::StringView, binder::Scope *> tempVarDeclStatements_ {};
};

}  // namespace panda::es2panda::parser

#endif
