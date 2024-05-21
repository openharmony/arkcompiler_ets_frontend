/*
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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
#include "checker/types/ets/etsEnumType.h"

namespace ark::es2panda::compiler {

class EnumLoweringPhase : public Phase {
public:
    EnumLoweringPhase() noexcept = default;
    std::string_view Name() const override
    {
        return "EnumLoweringPhase";
    }
    bool Perform(public_lib::Context *ctx, parser::Program *program) override;
    static util::UString GetQualifiedName(checker::ETSChecker *checker, const ir::TSEnumDeclaration *const enumDecl,
                                          const util::StringView &name);

    checker::ETSChecker *Checker()
    {
        return checker_;
    }

    varbinder::ETSBinder *Varbinder()
    {
        return varbinder_;
    }

private:
    [[nodiscard]] ir::ScriptFunction *MakeFunction(varbinder::FunctionParamScope *const paramScope,
                                                   ArenaVector<ir::Expression *> &&params,
                                                   ArenaVector<ir::Statement *> &&body,
                                                   ir::TypeNode *const returnTypeAnnotation,
                                                   const ir::TSEnumDeclaration *const enumDecl);

    void CreateEnumIntClassFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl);
    void CreateEnumStringClassFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl);
    static void AppendParentNames(util::UString &qualifiedName, const ir::AstNode *const node);
    [[nodiscard]] ir::Identifier *MakeQualifiedIdentifier(const ir::TSEnumDeclaration *const enumDecl,
                                                          const util::StringView &name);

    template <typename ElementMaker>
    [[nodiscard]] ir::Identifier *MakeArray(const ir::TSEnumDeclaration *const enumDecl,
                                            ir::ClassDefinition *globalClass, const util::StringView &name,
                                            ir::TypeNode *const typeAnnotation, ElementMaker &&elementMaker);

    ir::Identifier *CreateEnumNamesArray(const ir::TSEnumDeclaration *const enumDecl);

    ir::Identifier *CreateEnumValuesArray(const ir::TSEnumDeclaration *const enumDecl);
    ir::Identifier *CreateEnumStringValuesArray(const ir::TSEnumDeclaration *const enumDecl);
    ir::Identifier *CreateEnumItemsArray(const ir::TSEnumDeclaration *const enumDecl);
    void CreateEnumFromIntMethod(ir::TSEnumDeclaration const *const enumDecl, ir::Identifier *const itemsArrayIdent);

    void CreateEnumToStringMethod(ir::TSEnumDeclaration const *const enumDecl,
                                  ir::Identifier *const stringValuesArrayIdent);

    void CreateEnumGetValueMethod(ir::TSEnumDeclaration const *const enumDecl, ir::Identifier *const valuesArrayIdent);
    void CreateEnumGetNameMethod(ir::TSEnumDeclaration const *const enumDecl, ir::Identifier *const namesArrayIdent);
    void CreateEnumValueOfMethod(ir::TSEnumDeclaration const *const enumDecl, ir::Identifier *const namesArrayIdent);
    void CreateEnumValuesMethod(ir::TSEnumDeclaration const *const enumDecl, ir::Identifier *const itemsArrayIdent);

private:
    checker::ETSChecker *checker_ {nullptr};
    parser::Program *program_ {nullptr};
    varbinder::ETSBinder *varbinder_ {nullptr};
};

}  // namespace ark::es2panda::compiler

#endif  // ES2PANDA_COMPILER_ENUM_PRE_CHECK_LOWERING_H
