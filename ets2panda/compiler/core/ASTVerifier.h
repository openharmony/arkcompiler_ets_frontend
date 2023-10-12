/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
#define ES2PANDA_COMPILER_CORE_ASTVERIFIER_H

#include "parser/program/program.h"

namespace panda::es2panda::compiler {

class ASTVerifier {
public:
    using ErrorMessages = std::vector<std::string>;
    NO_COPY_SEMANTIC(ASTVerifier);
    NO_MOVE_SEMANTIC(ASTVerifier);

    ASTVerifier() = default;
    ~ASTVerifier() = default;

    bool IsCorrectProgram(const parser::Program *program);
    bool HaveParents(const ir::AstNode *ast);
    bool HasParent(const ir::AstNode *ast);
    bool HaveTypes(const ir::AstNode *ast);
    bool HasType(const ir::AstNode *ast);
    bool HaveVariables(const ir::AstNode *ast);
    bool HasVariable(const ir::AstNode *ast);
    bool HasScope(const ir::AstNode *ast);
    bool HaveScopes(const ir::AstNode *ast);

    ErrorMessages GetErrorMessages()
    {
        return error_messages_;
    }

private:
    ErrorMessages error_messages_;
};

std::string ToStringHelper(const ir::AstNode *ast);

}  // namespace panda::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
