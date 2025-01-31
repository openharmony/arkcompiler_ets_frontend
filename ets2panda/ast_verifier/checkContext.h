/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKCONTEXT_H
#define ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKCONTEXT_H

#include "generated/options.h"
#include "ir/astNode.h"
#include "utils/json_builder.h"

namespace ark::es2panda::compiler::ast_verifier {

enum class CheckDecision { CORRECT, INCORRECT };
enum class CheckAction { CONTINUE, SKIP_SUBTREE };

using CheckResult = std::tuple<CheckDecision, CheckAction>;
using VerifierInvariants = util::gen::ast_verifier::Enum;
using Enum = VerifierInvariants;

class CheckMessage {
public:
    explicit CheckMessage(util::StringView cause, const ir::AstNode *node) : cause_ {cause}, node_ {node} {}

    std::function<void(JsonObjectBuilder &)> DumpJSON() const
    {
        return [this](JsonObjectBuilder &body) {
            body.AddProperty("cause", cause_);
            body.AddProperty("ast", node_->DumpJSON());
            body.AddProperty("line", node_->Start().line + 1);
        };
    }

    std::string ToString() const
    {
        return cause_ + "(AstNodeType::" + std::string(ir::ToString(node_->Type())) + ", line " +
               std::to_string(node_->Start().line + 1) + ')';
    }

    const auto &Cause() const
    {
        return cause_;
    }

private:
    std::string cause_;
    const ir::AstNode *node_;
};

using Messages = std::vector<CheckMessage>;

class CheckContext {
public:
    void Init()
    {
        messages_.clear();
    }

    void AddCheckMessage(const std::string &cause, const ir::AstNode &node);

    auto &&MoveMessages() &&
    {
        return std::move(messages_);
    }

    bool HasMessages() const
    {
        return !messages_.empty();
    }

private:
    Messages messages_;
};

template <VerifierInvariants ENUM>
class InvariantBase : public CheckContext {
public:
    constexpr static VerifierInvariants ID = ENUM;
    constexpr static std::string_view NAME = util::gen::ast_verifier::ToString(ID);
    CheckResult VerifyNode(const ir::AstNode *ast);
};

template <VerifierInvariants ID>
class RecursiveInvariant : public InvariantBase<ID> {
public:
    void VerifyAst(const ir::AstNode *ast);
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKCONTEXT_H
