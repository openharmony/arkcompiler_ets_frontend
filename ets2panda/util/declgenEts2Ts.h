/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "plugins/ecmascript/es2panda/parser/program/program.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "libpandabase/os/file.h"

#ifndef ES2PANDA_UTIL_DECLGEN_ETS2TS_H
#define ES2PANDA_UTIL_DECLGEN_ETS2TS_H

namespace panda::es2panda::util {

// Consume program after checker stage and generate out_path typescript file with declarations
bool GenerateTsDeclarations(checker::ETSChecker *checker, const panda::es2panda::parser::Program *program,
                            const std::string &out_path);

class TSDeclGen {
public:
    TSDeclGen(checker::ETSChecker *checker, const panda::es2panda::parser::Program *program)
        : checker_(checker), program_(program)
    {
    }

    std::stringstream &Output()
    {
        return output_;
    }

    void Generate();

    static constexpr std::string_view INDENT = "    ";

private:
    void ThrowError(std::string_view message, const lexer::SourcePosition &pos);
    std::string GetKeyName(const ir::Expression *key);

    void GenType(const checker::Type *checker_type);
    void GenFunctionType(const checker::ETSFunctionType *function_type,
                         const ir::MethodDefinition *method_def = nullptr);
    void GenObjectType(const checker::ETSObjectType *object_type);
    void GenEnumType(const checker::ETSEnumType *enum_type);

    void GenImportDeclaration(const ir::ETSImportDeclaration *import_declaration);
    void GenTypeAliasDeclaration(const ir::TSTypeAliasDeclaration *type_alias);
    void GenEnumDeclaration(const ir::TSEnumDeclaration *enum_decl);
    void GenInterfaceDeclaration(const ir::TSInterfaceDeclaration *interface_decl);
    void GenClassDeclaration(const ir::ClassDeclaration *class_decl);
    void GenMethodDeclaration(const ir::MethodDefinition *method_def);
    void GenPropDeclaration(const ir::ClassProperty *class_prop);
    void GenLiteral(const ir::Literal *literal);

    template <class T>
    void GenModifier(const T *node);
    void GenTypeParameters(const ir::TSTypeParameterDeclaration *type_params);

    template <class T, class CB>
    void GenCommaSeparated(const T &container, const CB &cb);

    void Out() {}
    template <class F, class... T>
    void Out(F &&first, T &&...rest)
    {
        output_ << first;
        Out(std::forward<T>(rest)...);
    }
    void OutEndl(const std::size_t count = 1)
    {
        panda::os::file::File::GetEndLine(output_, count);
    }

    void ResetState()
    {
        state_ = GenState();
    }

    struct GenState {
        bool in_interface {false};
        bool in_global_class {false};
        std::string current_class_descriptor {};
    } state_ {};

    std::stringstream output_ {};
    checker::ETSChecker *checker_ {};
    const panda::es2panda::parser::Program *program_ {};
};
}  // namespace panda::es2panda::util

#endif  // ES2PANDA_UTIL_DECLGEN_ETS2TS_H
