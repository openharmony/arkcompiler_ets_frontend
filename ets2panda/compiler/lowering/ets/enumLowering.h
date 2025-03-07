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

#ifndef ES2PANDA_COMPILER_ENUM_PRE_CHECK_LOWERING_H
#define ES2PANDA_COMPILER_ENUM_PRE_CHECK_LOWERING_H

#include "compiler/lowering/phase.h"

namespace ark::es2panda::compiler {

class EnumLoweringPhase : public PhaseForDeclarations {
public:
    struct DeclarationFlags {
        // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
        bool isTopLevel;
        bool isLocal;
        bool isNamespace;
        // NOLINTEND(misc-non-private-member-variables-in-classes)

        [[nodiscard]] bool IsValid() const noexcept
        {
            return isTopLevel || isLocal || isNamespace;
        }
    };

    EnumLoweringPhase() noexcept = default;
    std::string_view Name() const override
    {
        return "EnumLoweringPhase";
    }
    bool PerformForModule(public_lib::Context *ctx, parser::Program *program) override;
    static util::UString GetEnumClassName(checker::ETSChecker *checker, const ir::TSEnumDeclaration *const enumDecl);
    checker::ETSChecker *Checker()
    {
        return checker_;
    }

    varbinder::ETSBinder *Varbinder()
    {
        return varbinder_;
    }

private:
    struct FunctionInfo {
        ArenaVector<ir::Expression *> &&params;
        ArenaVector<ir::Statement *> &&body;
        ir::TypeNode *returnTypeAnnotation;
        const ir::TSEnumDeclaration *enumDecl;
        ir::ModifierFlags flags;
    };

    void LogSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos) const;

    template <typename TypeNode>
    bool CheckEnumMemberType(const ArenaVector<ir::AstNode *> &enumMembers, bool &hasLoggedError);

    [[nodiscard]] ir::ScriptFunction *MakeFunction(FunctionInfo &&functionInfo);
    ir::ClassDeclaration *CreateClass(ir::TSEnumDeclaration *const enumDecl, const DeclarationFlags flags);
    ir::ClassProperty *CreateOrdinalField(ir::ClassDefinition *const enumClass);
    void CreateCCtorForEnumClass(ir::ClassDefinition *const enumClass);
    void CreateCtorForEnumClass(ir::ClassDefinition *const enumClass);
    ir::ScriptFunction *CreateFunctionForCtorOfEnumClass(ir::ClassDefinition *const enumClass);

    void ProcessEnumClassDeclaration(ir::TSEnumDeclaration *const enumDecl, const DeclarationFlags &flags,
                                     ir::ClassDeclaration *enumClassDecl);
    void CreateEnumIntClassFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl, const DeclarationFlags flags);
    void CreateEnumStringClassFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl, const DeclarationFlags flags);
    static void AppendParentNames(util::UString &qualifiedName, const ir::AstNode *const node);
    template <typename ElementMaker>
    [[nodiscard]] ir::Identifier *MakeArray(const ir::TSEnumDeclaration *const enumDecl, ir::ClassDefinition *enumClass,
                                            const util::StringView &name, ir::TypeNode *const typeAnnotation,
                                            ElementMaker &&elementMaker);

    ir::Identifier *CreateEnumNamesArray(const ir::TSEnumDeclaration *const enumDecl, ir::ClassDefinition *enumClass);
    ir::Identifier *CreateEnumValuesArray(const ir::TSEnumDeclaration *const enumDecl, ir::ClassDefinition *enumClass);
    ir::Identifier *CreateEnumStringValuesArray(const ir::TSEnumDeclaration *const enumDecl,
                                                ir::ClassDefinition *enumClass);
    ir::Identifier *CreateEnumItemsArray(const ir::TSEnumDeclaration *const enumDecl, ir::ClassDefinition *enumClass);
    ir::Identifier *CreateBoxedEnumItemsArray(const ir::TSEnumDeclaration *const enumDecl,
                                              ir::ClassDefinition *enumClass);

    void CreateEnumFromIntMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                                 ir::Identifier *const arrayIdent, const util::StringView &methodName,
                                 const util::StringView &returnTypeName);
    void CreateEnumToStringMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                                  ir::Identifier *const stringValuesArrayIdent);
    void CreateEnumValueOfMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                                 ir::Identifier *const valuesArrayIdent);
    void CreateEnumGetNameMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                                 ir::Identifier *const namesArrayIdent);
    void CreateEnumGetValueOfMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                                    ir::Identifier *const namesArrayIdent);
    void CreateEnumValuesMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                                ir::Identifier *const itemsArrayIdent);
    void CreateUnboxingMethod(ir::TSEnumDeclaration const *const enumDecl, ir::ClassDefinition *const enumClass,
                              ir::Identifier *const itemsArrayIdent);
    void SetDefaultPositionInUnfilledClassNodes(const ir::ClassDeclaration *enumClassDecl,
                                                ir::TSEnumDeclaration const *const enumDecl);

    ArenaAllocator *Allocator();

private:
    public_lib::Context *context_ {nullptr};
    checker::ETSChecker *checker_ {nullptr};
    parser::Program *program_ {nullptr};
    varbinder::ETSBinder *varbinder_ {nullptr};
};

}  // namespace ark::es2panda::compiler

#endif  // ES2PANDA_COMPILER_ENUM_PRE_CHECK_LOWERING_H
