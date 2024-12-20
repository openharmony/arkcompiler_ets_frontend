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

class CheckContext;
enum class CheckDecision { CORRECT, INCORRECT };
enum class CheckAction { CONTINUE, SKIP_SUBTREE };

using CheckResult = std::tuple<CheckDecision, CheckAction>;
using VerifierInvariants = util::gen::verifier_invariants::Enum;

template <VerifierInvariants ENUM>
class InvariantBase {
public:
    constexpr static VerifierInvariants ID = ENUM;
    constexpr static std::string_view NAME = util::gen::verifier_invariants::ToString(ID);
    CheckResult VerifyNode(CheckContext *ctx, const ir::AstNode *ast);
};

template <VerifierInvariants ID>
class RecursiveInvariant : public InvariantBase<ID> {
public:
    void VerifyAst(CheckContext *ctx, const ir::AstNode *ast);
};

enum class CheckSeverity { ERROR, WARNING, UNKNOWN };
inline std::string CheckSeverityString(CheckSeverity value)
{
    switch (value) {
        case CheckSeverity::ERROR:
            return "error";
        case CheckSeverity::WARNING:
            return "warning";
        default:
            UNREACHABLE();
    }
}

class CheckMessage {
public:
    explicit CheckMessage(VerifierInvariants id, util::StringView cause, util::StringView message, size_t line)
        : invariantId_ {id}, cause_ {cause}, message_ {message}, line_ {line}
    {
    }

    VerifierInvariants InvariantId() const
    {
        return invariantId_;
    }

    std::string Cause() const
    {
        return cause_;
    }

    std::function<void(JsonObjectBuilder &)> DumpJSON(CheckSeverity severity, const std::string &sourceName,
                                                      const std::string &phaseName) const
    {
        return [sourceName, phaseName, severity, this](JsonObjectBuilder &body) {
            body.AddProperty("severity", CheckSeverityString(severity));
            body.AddProperty("invariant", util::gen::verifier_invariants::ToString(invariantId_));
            body.AddProperty("cause", cause_);
            body.AddProperty("ast", message_);
            body.AddProperty("line", line_ + 1);
            body.AddProperty("source", sourceName);
            body.AddProperty("phase", phaseName);
        };
    }

private:
    VerifierInvariants invariantId_;
    std::string cause_;
    std::string message_;
    size_t line_;
};

using Messages = std::vector<CheckMessage>;

class CheckContext {
public:
    void AddCheckMessage(const std::string &cause, const ir::AstNode &node, const lexer::SourcePosition &from)
    {
        const auto loc = from.line;
        const auto &&dump = node.DumpJSON();
        messages_.emplace_back(invariantId_, cause.data(), dump.data(), loc);
    }

    void SetInvariantId(VerifierInvariants id)
    {
        invariantId_ = id;
    }

    Messages GetMessages()
    {
        return messages_;
    }

private:
    Messages messages_;
    VerifierInvariants invariantId_ {VerifierInvariants::INVALID};
};

}  // namespace ark::es2panda::compiler::ast_verifier

#endif  // ES2PANDA_COMPILER_CORE_AST_VERIFIER_CHECKCONTEXT_H
