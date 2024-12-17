/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
using VerifierInvariants = util::gen::verifier_invariants::Enum;

class CheckMessage {
public:
    explicit CheckMessage(util::StringView cause, util::StringView message, size_t line)
        : cause_ {cause}, message_ {message}, line_ {line}
    {
    }

    std::function<void(JsonObjectBuilder &)> DumpJSON() const
    {
        return [this](JsonObjectBuilder &body) {
            body.AddProperty("cause", cause_);
            body.AddProperty("ast", message_);
            body.AddProperty("line", line_ + 1);
        };
    }

    const auto &Cause() const
    {
        return cause_;
    }

private:
    std::string cause_;
    std::string message_;
    size_t line_;
};

using Messages = std::vector<CheckMessage>;

class CheckContext {
public:
    void Init()
    {
        messages_.clear();
    }

    void AddCheckMessage(const std::string &cause, const ir::AstNode &node)
    {
        const auto loc = node.Start().line;
        const auto &&dump = node.DumpJSON();
        messages_.emplace_back(cause.data(), dump.data(), loc);
    }

    void AppendMessages(const Messages &messages)
    {
        messages_.insert(messages_.end(), messages.begin(), messages.end());
    }

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
    constexpr static std::string_view NAME = util::gen::verifier_invariants::ToString(ID);
    CheckResult VerifyNode(const ir::AstNode *ast);
};

template <VerifierInvariants ID>
class RecursiveInvariant : public InvariantBase<ID> {
public:
    void VerifyAst(const ir::AstNode *ast);
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKCONTEXT_H
