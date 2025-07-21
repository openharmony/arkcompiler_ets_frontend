/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_LSP_INCLUDE_SIGNATURE_HELP_H
#define ES2PANDA_LSP_INCLUDE_SIGNATURE_HELP_H

#include "create_type_help_items.h"
#include <optional>
#include <utility>
#include <variant>
#include <vector>
#include <cstddef>
#include "cancellation_token.h"
#include "ir/astNode.h"
#include "public/es2panda_lib.h"
#include "public/public.h"
#include "signature_help_items.h"

namespace ark::es2panda::lsp {

enum class SignatureHelpTriggerCharacter {
    COMMA,      // Represents ","
    OPENPAREN,  // Represents "("
    LESSTHAN    // Represents "<"
};
enum class SignatureHelpRetriggerCharacter {
    COMMA,      // Represents ","
    OPENPAREN,  // Represents "("
    LESSTHAN,   // Represents "<"
    CLOSEPAREN  // Represents ")"
};

enum CandidateOrTypeKind { CANDIDATE, TYPEENUM };
struct TypeInfo {
private:
    CandidateOrTypeKind kind_;
    const ir::AstNode *symbol_;

public:
    TypeInfo(CandidateOrTypeKind kind, const ir::AstNode *symbol) : kind_(kind), symbol_(symbol) {}

    void SetKind(CandidateOrTypeKind newKind)
    {
        kind_ = newKind;
    }
    void SetSymbol(const ir::AstNode *newSymbol)
    {
        symbol_ = newSymbol;
    }
    CandidateOrTypeKind GetKind() const
    {
        return kind_;
    }
    const ir::AstNode *GetSymbol() const
    {
        return symbol_;
    }

    TypeInfo() = default;
};

struct CandidateInfo {
private:
    CandidateOrTypeKind kind_;
    std::vector<checker::Signature *> signatures_;
    checker::Signature *resolvedSignature_;

public:
    CandidateInfo(CandidateOrTypeKind kind, std::vector<checker::Signature *> &signatures,
                  checker::Signature *resolvedSignature)
        : kind_(kind), signatures_(signatures), resolvedSignature_(resolvedSignature)
    {
    }

    void SetKind(CandidateOrTypeKind newKind)
    {
        kind_ = newKind;
    }
    void SetSignatures(const std::vector<checker::Signature *> &newSignatures)
    {
        signatures_ = newSignatures;
    }
    void SetResolvedSignature(checker::Signature *newResolvedSignature)
    {
        resolvedSignature_ = newResolvedSignature;
    }
    CandidateOrTypeKind GetKind() const
    {
        return kind_;
    }
    std::vector<checker::Signature *> &GetSignatures()
    {
        return signatures_;
    }
    checker::Signature *GetResolvedSignature()
    {
        return resolvedSignature_;
    }
    CandidateInfo() : kind_(CandidateOrTypeKind::CANDIDATE), resolvedSignature_(nullptr) {}
};

using InfoType = std::variant<struct CandidateInfo, struct TypeInfo>;

struct SignatureHelpInvokedReason {
private:
    const char *kind_ = "invoked";
    SignatureHelpTriggerCharacter triggerCharacter_;

public:
    explicit SignatureHelpInvokedReason(SignatureHelpTriggerCharacter trigger) : triggerCharacter_(trigger) {}
    SignatureHelpInvokedReason() : triggerCharacter_(SignatureHelpTriggerCharacter::LESSTHAN) {}

    const char *GetKind() const
    {
        return kind_;
    }

    SignatureHelpTriggerCharacter GetTriggerCharacter() const
    {
        return triggerCharacter_;
    }

    void SetTriggerCharacter(SignatureHelpTriggerCharacter newTriggerCharacter)
    {
        triggerCharacter_ = newTriggerCharacter;
    }
};

struct SignatureHelpCharacterTypedReason {
private:
    const char *kind_ = "characterTyped";
    SignatureHelpTriggerCharacter triggerCharacter_;

public:
    explicit SignatureHelpCharacterTypedReason() : triggerCharacter_(SignatureHelpTriggerCharacter::LESSTHAN) {}

    const char *GetKind() const
    {
        return kind_;
    }
    SignatureHelpTriggerCharacter GetTriggerCharacter() const
    {
        return triggerCharacter_;
    }
    void SetTriggerCharacter(SignatureHelpTriggerCharacter newTriggerCharacter)
    {
        triggerCharacter_ = newTriggerCharacter;
    }
    explicit SignatureHelpCharacterTypedReason(SignatureHelpTriggerCharacter trigger) : triggerCharacter_(trigger) {}
};

struct SignatureHelpRetriggeredReason {
private:
    const char *kind_ = "retrigger";
    SignatureHelpRetriggerCharacter triggerCharacter_;

public:
    SignatureHelpRetriggeredReason() : triggerCharacter_(SignatureHelpRetriggerCharacter::LESSTHAN) {}
    explicit SignatureHelpRetriggeredReason(SignatureHelpRetriggerCharacter trigger) : triggerCharacter_(trigger) {}

    const char *GetKind() const
    {
        return kind_;
    }
    SignatureHelpRetriggerCharacter GetTriggerCharacter() const
    {
        return triggerCharacter_;
    }
    void SetTriggerCharacter(SignatureHelpRetriggerCharacter newTriggerCharacter)
    {
        triggerCharacter_ = newTriggerCharacter;
    }
};

using SignatureHelpTriggerReason =
    std::variant<struct SignatureHelpInvokedReason, struct SignatureHelpCharacterTypedReason,
                 struct SignatureHelpRetriggeredReason>;

struct ContextualSignatureLocationInfo {
private:
    std::vector<ArgumentListInfo> list_;
    size_t argumentIndex_;
    size_t argumentCount_;
    TextSpan argumentsSpan_ = {0, 0};

public:
    ContextualSignatureLocationInfo(std::vector<ArgumentListInfo> &list, const size_t argumentIndex,
                                    const size_t argumentCount, const TextSpan argumentsSpan)
        : list_(list), argumentIndex_(argumentIndex), argumentCount_(argumentCount), argumentsSpan_(argumentsSpan)
    {
    }

    void SetList(const std::vector<ArgumentListInfo> &newList)
    {
        list_ = newList;
    }
    void SetArgumentIndex(size_t newArgumentIndex)
    {
        argumentIndex_ = newArgumentIndex;
    }
    void SetArgumentCount(size_t newArgumentCount)
    {
        argumentCount_ = newArgumentCount;
    }
    void SetArgumentsSpan(TextSpan newArgumentsSpan)
    {
        argumentsSpan_ = newArgumentsSpan;
    }
    const std::vector<ArgumentListInfo> &GetList() const
    {
        return list_;
    }
    size_t GetArgumentIndex() const
    {
        return argumentIndex_;
    }
    size_t GetArgumentCount() const
    {
        return argumentCount_;
    }
    const TextSpan &GetArgumentsSpan() const
    {
        return argumentsSpan_;
    }
    ContextualSignatureLocationInfo() : argumentIndex_(0), argumentCount_(0) {}
};

struct ContextualSignatureLocationInfoWithNode {
private:
    ir::AstNode *node_;
    size_t argumentIndex_;
    size_t argumentCount_;
    TextSpan argumentsSpan_ = {0, 0};

public:
    ContextualSignatureLocationInfoWithNode(ir::AstNode *node, const size_t argumentIndex, const size_t argumentCount,
                                            const TextSpan argumentsSpan)
        : node_(node), argumentIndex_(argumentIndex), argumentCount_(argumentCount), argumentsSpan_(argumentsSpan)
    {
    }

    void SetNode(ir::AstNode *newNode)
    {
        node_ = newNode;
    }
    void SetArgumentIndex(size_t newArgumentIndex)
    {
        argumentIndex_ = newArgumentIndex;
    }
    void SetArgumentCount(size_t newArgumentCount)
    {
        argumentCount_ = newArgumentCount;
    }
    void SetArgumentsSpan(TextSpan newArgumentsSpan)
    {
        argumentsSpan_ = newArgumentsSpan;
    }
    ir::AstNode *GetNode() const
    {
        return node_;
    }
    size_t GetArgumentIndex() const
    {
        return argumentIndex_;
    }
    size_t GetArgumentCount() const
    {
        return argumentCount_;
    }
    const TextSpan &GetArgumentsSpan() const
    {
        return argumentsSpan_;
    }
};

bool IsSyntacticOwner(const ir::AstNode *node);
size_t GetArgumentCount(ir::AstNode *node, bool ignoreTrailingComma);
ir::AstNode *GetHighestBinary(const ir::AstNode *node);
TextSpan CreateTextSpanForNode(const ir::AstNode *node);
size_t CountBinaryExpressionParameters(ir::AstNode *node);
std::vector<ArgumentListInfo> GetArgumentOrParameterListAndIndex(ir::AstNode *node,
                                                                 std::vector<ArgumentListInfo> &list);
std::optional<ContextualSignatureLocationInfo> GetContextualSignatureLocationInfo(ir::AstNode *node);
std::optional<ArgumentListInfo> GetImmediatelyContainingArgumentInfo(ir::AstNode *node, size_t position);
std::optional<ArgumentListInfo> TryGetParameterInfo(ir::AstNode *node);
std::optional<ArgumentListInfo> GetImmediatelyContainingArgumentOrContextualParameterInfo(ir::AstNode *node,
                                                                                          size_t position,
                                                                                          ir::AstNode *parent);
std::optional<ArgumentListInfo> GetContainingArgumentInfo(ir::AstNode *node, size_t position, bool isManuallyInvoked);
size_t GetArgumentIndexForTemplatePiece(size_t spanIndex, ir::AstNode *node, size_t position);
ir::AstNode *GetChildListThatStartsWithOpenerToken(ir::AstNode *parent, ir::AstNode *openerToken);
ir::AstNode *FindTokenOnLeftOfPosition(es2panda_Context *context, size_t position);

SignatureHelpItems GetSignatureHelpItems(es2panda_Context *ctx, size_t position,
                                         SignatureHelpTriggerReason triggeredReason,
                                         CancellationToken cancellationToken);
std::optional<InfoType> GetCandidateOrTypeInfo(const std::optional<ArgumentListInfo> info, ir::AstNode *parent,
                                               const bool onlyUseSyntacticOwners);
checker::Signature *GetResolvedSignatureForSignatureHelp(const ir::AstNode *call, const ir::AstNode *parent,
                                                         std::vector<checker::Signature *> &candidates);

}  // namespace ark::es2panda::lsp

#endif
