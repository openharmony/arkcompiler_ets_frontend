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
#include <utility>
#include <variant>

namespace ark::es2panda::lsp {

using Type = checker::Type;

// Define constants for symbol kinds
constexpr const char *SYMBOL_KIND_PUNCTUATION = "punctuation";
constexpr const char *SYMBOL_KIND_KEYWORD = "keyword";
constexpr const char *SYMBOL_KIND_CLASS_NAME = "className";
constexpr const char *SYMBOL_KIND_STRUCT_NAME = "structName";
constexpr const char *SYMBOL_KIND_ENUM_NAME = "enumName";
constexpr const char *SYMBOL_KIND_PARAM_NAME = "paramName";
constexpr const char *SYMBOL_KIND_TYPE = "type";

struct SignatureHelpParameter {
private:
    std::string name_;
    ArenaVector<SymbolDisplayPart> documentation_;
    ArenaVector<SymbolDisplayPart> displayParts_;

public:
    explicit SignatureHelpParameter(ArenaAllocator *allocator)
        : documentation_(allocator->Adapter()), displayParts_(allocator->Adapter())
    {
    }
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
    const ArenaVector<SymbolDisplayPart> &GetDocumentation() const
    {
        return documentation_;
    }
    const ArenaVector<SymbolDisplayPart> &GetDisplayParts() const
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
    ArenaVector<SymbolDisplayPart> prefixDisplayParts_;
    ArenaVector<SymbolDisplayPart> suffixDisplayParts_;
    ArenaVector<SymbolDisplayPart> separatorDisplayParts_;
    ArenaVector<SignatureHelpParameter> parameters_;
    ArenaVector<SymbolDisplayPart> documentation_;

public:
    explicit SignatureHelpItem(ArenaAllocator *allocator)
        : prefixDisplayParts_(allocator->Adapter()),
          suffixDisplayParts_(allocator->Adapter()),
          separatorDisplayParts_(allocator->Adapter()),
          parameters_(allocator->Adapter()),
          documentation_(allocator->Adapter())
    {
    }

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
        prefixDisplayParts_.push_back(SymbolDisplayPart(text, kind));
    }

    void SetParameters(SignatureHelpParameter &parameter)
    {
        parameters_.push_back(parameter);
    }
    void SetDocumentation(const std::string &text, const std::string &kind)
    {
        documentation_.push_back(SymbolDisplayPart(text, kind));
    }

    const ArenaVector<SymbolDisplayPart> &GetPrefixDisplayParts() const
    {
        return prefixDisplayParts_;
    }
    const ArenaVector<SymbolDisplayPart> &GetSuffixDisplayParts() const
    {
        return suffixDisplayParts_;
    }
    const ArenaVector<SymbolDisplayPart> &GetSeparatorDisplayParts() const
    {
        return separatorDisplayParts_;
    }
    const ArenaVector<SignatureHelpParameter> &GetParameters() const
    {
        return parameters_;
    }
    const ArenaVector<SymbolDisplayPart> &GetDocumentation() const
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
    ArenaVector<SignatureHelpItem> items_;
    TextSpan applicableSpan_ {0, 0};
    size_t selectedItemIndex_ {0};
    size_t argumentIndex_ {0};
    size_t argumentCount_ {0};

public:
    explicit SignatureHelpItems(ArenaAllocator *allocator) : items_(allocator->Adapter()) {}

    void SetItems(const SignatureHelpItem &item)
    {
        items_.push_back(item);
    }
    void SetApplicableSpan(const size_t &start, const size_t &line)
    {
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
    const ArenaVector<SignatureHelpItem> &GetItems() const
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
    ir::CallExpression *callExpressionNode = nullptr;
};

struct TypeArgsInvocation {
    InvocationKind kind = InvocationKind::TYPE_ARGS;
    ir::Identifier *identifierNode = nullptr;
};

struct ContextualInvocation {
    InvocationKind kind = InvocationKind::CONTEXTUAL;
    checker::Signature *signature = nullptr;
    ir::AstNode *node = nullptr;
};

using Invocation = std::variant<CallInvocation, TypeArgsInvocation, ContextualInvocation>;

void GetLocalTypeParametersOfClassOrInterfaceOrTypeAlias(const ir::AstNode *node, ArenaVector<Type *> &result);
ArenaVector<Type *> GetEffectiveTypeParameterDeclarations(const ir::AstNode *node, ArenaVector<Type *> &result);

void GetTypeHelpItem(ArenaVector<Type *> *typeParameters, const ir::AstNode *node, ArenaAllocator *allocator,
                     SignatureHelpItem &result);

SignatureHelpItems CreateTypeHelpItems(ArenaAllocator *allocator, ir::AstNode *node, lexer::SourceRange location,
                                       lexer::SourcePosition applicableSpan);
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