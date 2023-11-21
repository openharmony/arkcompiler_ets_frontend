/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ir/astNode.h"
#include "lexer/token/sourceLocation.h"
#include "util/ustring.h"
#include "utils/arena_containers.h"
#include "varbinder/variable.h"

namespace panda::es2panda::compiler {

class ASTVerifier final {
public:
    struct Error {
        std::string message;
        lexer::SourceLocation location;
    };
    struct NamedError {
        util::StringView check_name;
        Error error;
    };
    using Errors = ArenaVector<NamedError>;

    using CheckFunction = std::function<bool(const ir::AstNode *)>;
    struct NamedCheck {
        util::StringView check_name;
        CheckFunction check;
    };
    using Checks = ArenaVector<NamedCheck>;

    NO_COPY_SEMANTIC(ASTVerifier);
    NO_MOVE_SEMANTIC(ASTVerifier);

    explicit ASTVerifier(ArenaAllocator *allocator, bool save_errors = true, util::StringView source_code = "");
    ~ASTVerifier() = default;

    using CheckSet = ArenaSet<util::StringView>;

    /**
     * @brief Run all existing checks on some ast node (and consequently it's children)
     * @param ast AstNode which will be analyzed
     * @return bool Result of analysis
     */
    bool VerifyFull(const ir::AstNode *ast);

    /**
     * @brief Run some particular checks on some ast node
     * @note Checks must be supplied as strings to check_set, additionally check
     * name can be suffixed by `Recursive` string to include recursive analysis of provided node
     * @param ast AstNode which will be analyzed
     * @param check_set Set of strings which will be used as check names
     * @return bool Result of analysis
     */
    bool Verify(const ir::AstNode *ast, const CheckSet &check_set);

    Errors GetErrors() const
    {
        return named_errors_;
    }

private:
    bool HasParent(const ir::AstNode *ast);
    bool HasType(const ir::AstNode *ast);
    bool HasVariable(const ir::AstNode *ast);
    bool HasScope(const ir::AstNode *ast);
    bool VerifyChildNode(const ir::AstNode *ast);
    bool VerifyScopeNode(const ir::AstNode *ast);
    bool CheckArithmeticExpression(const ir::AstNode *ast);
    bool IsForLoopCorrectInitialized(const ir::AstNode *ast);
    bool AreForLoopsCorrectInitialized(const ir::AstNode *ast);
    bool VerifyModifierAccess(const ir::AstNode *ast);
    bool VerifyExportAccess(const ir::AstNode *ast);

    bool HandleImportExportIdentifier(const ir::Identifier *ident, const ir::AstNode *call_expr = nullptr);
    bool CheckImportExportVariable(const varbinder::Variable *var, const ir::Identifier *ident, util::StringView name);
    bool CheckImportExportMethod(const varbinder::Variable *var_callee, const ir::AstNode *call_expr,
                                 util::StringView name);

    void AddError(const std::string &message, const lexer::SourcePosition &from)
    {
        if (save_errors_) {
            const auto loc = index_.has_value() ? index_->GetLocation(from) : lexer::SourceLocation {};
            encountered_errors_.emplace_back(Error {message, loc});
        }
    }

    bool ScopeEncloseVariable(const varbinder::LocalVariable *var);
    std::optional<varbinder::LocalVariable *> GetLocalScopeVariable(const ir::AstNode *ast);

private:
    std::optional<const lexer::LineIndex> index_;

    bool save_errors_;
    ArenaAllocator *allocator_;
    Errors named_errors_;
    ArenaVector<Error> encountered_errors_;
    Checks checks_;
    CheckSet all_checks_;
    std::unordered_set<util::StringView> imported_variables_;
};

std::string ToStringHelper(const ir::AstNode *ast);

}  // namespace panda::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_ASTVERIFIER_H
