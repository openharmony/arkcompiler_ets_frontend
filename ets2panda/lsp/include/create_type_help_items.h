/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ES2PANDA_LSP_CREATE_TYPE_HELP_ITEMS_H
#define ES2PANDA_LSP_CREATE_TYPE_HELP_ITEMS_H

#include "api.h"
#include <string>
#include "ir/astNode.h"
#include "lexer/token/sourceLocation.h"
#include "utils/arena_containers.h"
#include <checker/checker.h>
#include <checker/typeChecker/TypeChecker.h>
#include <utility>
#include <variant>
#include <vector>

namespace ark::es2panda::lsp {

// Define constants for symbol kinds
constexpr const char *SYMBOL_KIND_PUNCTUATION = "punctuation";
constexpr const char *SYMBOL_KIND_KEYWORD = "keyword";
constexpr const char *SYMBOL_KIND_CLASS_NAME = "className";
constexpr const char *SYMBOL_KIND_STRUCT_NAME = "structName";
constexpr const char *SYMBOL_KIND_ENUM_NAME = "enumName";
constexpr const char *SYMBOL_KIND_PARAM_NAME = "paramName";
constexpr const char *SYMBOL_KIND_TYPE = "type";

struct SymbolDisplayPart {
private:
    std::string text_;
    std::string kind_;

public:
    SymbolDisplayPart(std::string text, std::string kind) : text_(std::move(text)), kind_(std::move(kind)) {}

    void SetText(const std::string &newText)
    {
        text_ = newText;
    }
    void SetKind(const std::string &newKind)
    {
        kind_ = newKind;
    }
    const std::string &GetText() const
    {
        return text_;
    }
    const std::string &GetKind() const
    {
        return kind_;
    }
};

struct SignatureHelpParameter {
private:
    std::string name_;
    std::vector<SymbolDisplayPart> documentation_;
    std::vector<SymbolDisplayPart> displayParts_;

public:
    void SetName(const std::string &newName)
    {
        this->name_ = newName;
    }
    void SetDocumentation(const SymbolDisplayPart &part)
    {
        documentation_.push_back(part);
    }

    void SetDisplayParts(const SymbolDisplayPart &part)
    {
        displayParts_.push_back(part);
    }
    const std::string &GetName() const
    {
        return name_;
    }
    const std::vector<SymbolDisplayPart> &GetDocumentation() const
    {
        return documentation_;
    }
    const std::vector<SymbolDisplayPart> &GetDisplayParts() const
    {
        return displayParts_;
    }
    void Clear()
    {
        displayParts_.clear();
        documentation_.clear();
    }
};
struct SignatureHelpItem {
private:
    std::vector<SymbolDisplayPart> prefixDisplayParts_;
    std::vector<SymbolDisplayPart> suffixDisplayParts_;
    std::vector<SymbolDisplayPart> separatorDisplayParts_;
    std::vector<SignatureHelpParameter> parameters_;
    std::vector<SymbolDisplayPart> documentation_;

public:
    void SetPrefixDisplayParts(const SymbolDisplayPart &part)
    {
        prefixDisplayParts_.push_back(part);
    }

    void SetSuffixDisplayParts(const SymbolDisplayPart &part)
    {
        suffixDisplayParts_.push_back(part);
    }
    void SetSeparatorDisplayParts(const SymbolDisplayPart &part)
    {
        separatorDisplayParts_.push_back(part);
    }
    void SetPrefixDisplayParts(const std::string &text, const std::string &kind)
    {
        prefixDisplayParts_.emplace_back(SymbolDisplayPart(text, kind));
    }

    void SetParameters(SignatureHelpParameter &parameter)
    {
        parameters_.push_back(parameter);
    }
    void SetDocumentation(const std::string &text, const std::string &kind)
    {
        documentation_.emplace_back(SymbolDisplayPart(text, kind));
    }

    const std::vector<SymbolDisplayPart> &GetPrefixDisplayParts() const
    {
        return prefixDisplayParts_;
    }
    const std::vector<SymbolDisplayPart> &GetSuffixDisplayParts() const
    {
        return suffixDisplayParts_;
    }
    const std::vector<SymbolDisplayPart> &GetSeparatorDisplayParts() const
    {
        return separatorDisplayParts_;
    }
    const std::vector<SignatureHelpParameter> &GetParameters() const
    {
        return parameters_;
    }
    const std::vector<SymbolDisplayPart> &GetDocumentation() const
    {
        return documentation_;
    }
    void Clear()
    {
        prefixDisplayParts_.clear();
        suffixDisplayParts_.clear();
        separatorDisplayParts_.clear();
        for (auto parameter : parameters_) {
            parameter.Clear();
        }
        parameters_.clear();
        documentation_.clear();
    }
};

struct SignatureHelpItems {
private:
    std::vector<SignatureHelpItem> items_;
    TextSpan applicableSpan_ {0, 0};
    size_t selectedItemIndex_ {0};
    size_t argumentIndex_ {0};
    size_t argumentCount_ {0};

public:
    void SetItems(const SignatureHelpItem &item)
    {
        items_.push_back(item);
    }
    void SetApplicableSpan(const size_t &start, const size_t &line)
    {
        applicableSpan_.start = start;
        applicableSpan_.length = line;
        applicableSpan_.start = start;
        applicableSpan_.length = line;
    }
    void SetSelectedItemIndex(const size_t &index)
    {
        selectedItemIndex_ = index;
    }
    void SetArgumentIndex(const size_t &index)
    {
        argumentIndex_ = index;
    }
    void SetArgumentCount(const size_t &count)
    {
        argumentCount_ = count;
    }

    SignatureHelpItem &GetItem(size_t index)
    {
        return items_[index];
    }
    const std::vector<SignatureHelpItem> &GetItems() const
    {
        return items_;
    }
    const TextSpan &GetApplicableSpan() const
    {
        return applicableSpan_;
    }
    size_t GetSelectedItemIndex() const
    {
        return selectedItemIndex_;
    }
    size_t GetArgumentIndex() const
    {
        return argumentIndex_;
    }
    size_t GetArgumentCount() const
    {
        return argumentCount_;
    }
    void Clear()
    {
        for (auto item : items_) {
            item.Clear();
        }
        items_.clear();
    }
};

enum class InvocationKind { CALL, TYPE_ARGS, CONTEXTUAL };

struct CallInvocation {
    InvocationKind kind = InvocationKind::CALL;
    ir::AstNode *callExpressionNode = nullptr;
};

struct TypeArgsInvocation {
    InvocationKind kind = InvocationKind::TYPE_ARGS;
    ir::AstNode *identifierNode = nullptr;
};

struct ContextualInvocation {
    InvocationKind kind = InvocationKind::CONTEXTUAL;
    checker::Signature *signature = nullptr;
    ir::AstNode *node = nullptr;
};

using Invocation = std::variant<CallInvocation, TypeArgsInvocation, ContextualInvocation>;

void GetLocalTypeParametersOfClassOrInterfaceOrTypeAlias(const ir::AstNode *node, std::vector<checker::Type *> &result);
std::vector<checker::Type *> GetEffectiveTypeParameterDeclarations(const ir::AstNode *node,
                                                                   std::vector<checker::Type *> &result);

void GetTypeHelpItem(std::vector<checker::Type *> *typeParameters, const ir::AstNode *node, SignatureHelpItem &result);

SignatureHelpItems CreateTypeHelpItems(const ir::AstNode *node, lexer::SourceRange location, TextSpan applicableSpan);
inline SymbolDisplayPart CreatePunctuation(const std::string &punc)
{
    return SymbolDisplayPart(punc, SYMBOL_KIND_PUNCTUATION);
}

inline SymbolDisplayPart CreateKeyword(const std::string &keyword)
{
    return SymbolDisplayPart(keyword, SYMBOL_KIND_KEYWORD);
}

inline SymbolDisplayPart CreateClassName(const std::string &name)
{
    return SymbolDisplayPart(name, SYMBOL_KIND_CLASS_NAME);
}

inline SymbolDisplayPart CreateStructName(const std::string &name)
{
    return SymbolDisplayPart(name, SYMBOL_KIND_STRUCT_NAME);
}

inline SymbolDisplayPart CreateEnumName(const std::string &name)
{
    return SymbolDisplayPart(name, SYMBOL_KIND_ENUM_NAME);
}

inline SymbolDisplayPart CreateTypeName(std::string &type)
{
    return SymbolDisplayPart(type, SYMBOL_KIND_TYPE);
}

inline SymbolDisplayPart CreateParameterName(std::string &type)
{
    return SymbolDisplayPart(type, SYMBOL_KIND_PARAM_NAME);
}

}  // namespace ark::es2panda::lsp

#endif  // ES2PANDA_LSP_CREATE_TYPE_HELP_ITEMS_H