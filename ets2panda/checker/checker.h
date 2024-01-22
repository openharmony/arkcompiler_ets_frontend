/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_CHECKER_CHECKER_H
#define ES2PANDA_CHECKER_CHECKER_H

#include "varbinder/enumMemberResult.h"
#include "checker/checkerContext.h"
#include "checker/SemanticAnalyzer.h"
#include "checker/types/typeRelation.h"
#include "util/enumbitops.h"
#include "util/ustring.h"
#include "es2panda.h"

#include "macros.h"

#include <cstdint>
#include <initializer_list>
#include <unordered_map>
#include <unordered_set>

namespace panda::es2panda::parser {
class Program;
}  // namespace panda::es2panda::parser

namespace panda::es2panda::ir {
class AstNode;
class Expression;
class BlockStatement;
enum class AstNodeType;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::varbinder {
class VarBinder;
class Decl;
class EnumVariable;
class FunctionDecl;
class LocalVariable;
class Scope;
class Variable;
}  // namespace panda::es2panda::varbinder

namespace panda::es2panda::checker {
class ETSChecker;
class InterfaceType;
class GlobalTypesHolder;

using StringLiteralPool = std::unordered_map<util::StringView, Type *>;
using NumberLiteralPool = std::unordered_map<double, Type *>;
using FunctionParamsResolveResult = std::variant<std::vector<varbinder::LocalVariable *> &, bool>;
using InterfacePropertyMap =
    std::unordered_map<util::StringView, std::pair<varbinder::LocalVariable *, InterfaceType *>>;
using TypeOrNode = std::variant<Type *, ir::AstNode *>;
using IndexInfoTypePair = std::pair<Type *, Type *>;
using PropertyMap = std::unordered_map<util::StringView, varbinder::LocalVariable *>;
using ArgRange = std::pair<uint32_t, uint32_t>;

class Checker {
public:
    explicit Checker();
    virtual ~Checker() = default;
    NO_COPY_SEMANTIC(Checker);
    NO_MOVE_SEMANTIC(Checker);

    ArenaAllocator *Allocator()
    {
        return &allocator_;
    }

    varbinder::Scope *Scope() const
    {
        return scope_;
    }

    CheckerContext &Context()
    {
        return context_;
    }

    bool HasStatus(CheckerStatus status)
    {
        return (context_.Status() & status) != 0;
    }

    void RemoveStatus(CheckerStatus status)
    {
        context_.Status() &= ~status;
    }

    void AddStatus(CheckerStatus status)
    {
        context_.Status() |= status;
    }

    TypeRelation *Relation() const
    {
        return relation_;
    }

    GlobalTypesHolder *GetGlobalTypesHolder() const
    {
        return globalTypes_;
    }

    RelationHolder &IdenticalResults()
    {
        return identicalResults_;
    }

    RelationHolder &AssignableResults()
    {
        return assignableResults_;
    }

    RelationHolder &ComparableResults()
    {
        return comparableResults_;
    }

    [[nodiscard]] RelationHolder &UncheckedCastableResult() noexcept
    {
        return uncheckedCastableResults_;
    }

    RelationHolder &SupertypeResults()
    {
        return supertypeResults_;
    }

    std::unordered_set<const void *> &TypeStack()
    {
        return typeStack_;
    }

    virtual bool IsETSChecker()
    {
        return false;
    }

    ETSChecker *AsETSChecker()
    {
        return reinterpret_cast<ETSChecker *>(this);
    }

    const ETSChecker *AsETSChecker() const
    {
        return reinterpret_cast<const ETSChecker *>(this);
    }

    virtual bool StartChecker([[maybe_unused]] varbinder::VarBinder *varbinder, const CompilerOptions &options) = 0;
    virtual Type *CheckTypeCached(ir::Expression *expr) = 0;
    virtual Type *GetTypeOfVariable(varbinder::Variable *var) = 0;
    virtual void ResolveStructuredTypeMembers(Type *type) = 0;

    std::string FormatMsg(std::initializer_list<TypeErrorMessageElement> list);
    [[noreturn]] void ThrowTypeError(std::string_view message, const lexer::SourcePosition &pos);
    [[noreturn]] void ThrowTypeError(std::initializer_list<TypeErrorMessageElement> list,
                                     const lexer::SourcePosition &pos);
    void Warning(std::string_view message, const lexer::SourcePosition &pos) const;
    void ReportWarning(std::initializer_list<TypeErrorMessageElement> list, const lexer::SourcePosition &pos);

    bool IsTypeIdenticalTo(Type *source, Type *target);
    bool IsTypeIdenticalTo(Type *source, Type *target, const std::string &errMsg, const lexer::SourcePosition &errPos);
    bool IsTypeIdenticalTo(Type *source, Type *target, std::initializer_list<TypeErrorMessageElement> list,
                           const lexer::SourcePosition &errPos);
    bool IsTypeAssignableTo(Type *source, Type *target);
    bool IsTypeAssignableTo(Type *source, Type *target, const std::string &errMsg, const lexer::SourcePosition &errPos);
    bool IsTypeAssignableTo(Type *source, Type *target, std::initializer_list<TypeErrorMessageElement> list,
                            const lexer::SourcePosition &errPos);
    bool IsTypeComparableTo(Type *source, Type *target);
    bool IsTypeComparableTo(Type *source, Type *target, const std::string &errMsg, const lexer::SourcePosition &errPos);
    bool IsTypeComparableTo(Type *source, Type *target, std::initializer_list<TypeErrorMessageElement> list,
                            const lexer::SourcePosition &errPos);
    bool AreTypesComparable(Type *source, Type *target);
    bool IsTypeEqualityComparableTo(Type *source, Type *target);
    bool IsAllTypesAssignableTo(Type *source, Type *target);
    void SetAnalyzer(SemanticAnalyzer *analyzer);
    checker::SemanticAnalyzer *GetAnalyzer() const;

    friend class ScopeContext;
    friend class TypeStackElement;
    friend class SavedCheckerContext;

    varbinder::VarBinder *VarBinder() const;

protected:
    void Initialize(varbinder::VarBinder *varbinder);
    parser::Program *Program() const;
    void SetProgram(parser::Program *program);

private:
    ArenaAllocator allocator_;
    CheckerContext context_;
    GlobalTypesHolder *globalTypes_;
    TypeRelation *relation_;
    SemanticAnalyzer *analyzer_ {};
    varbinder::VarBinder *varbinder_ {};
    parser::Program *program_ {};
    varbinder::Scope *scope_ {};

    RelationHolder identicalResults_;
    RelationHolder assignableResults_;
    RelationHolder comparableResults_;
    RelationHolder uncheckedCastableResults_;
    RelationHolder supertypeResults_;

    std::unordered_set<const void *> typeStack_;
};

class TypeStackElement {
public:
    explicit TypeStackElement(Checker *checker, void *element, std::initializer_list<TypeErrorMessageElement> list,
                              const lexer::SourcePosition &pos)
        : checker_(checker), element_(element)
    {
        if (!checker->typeStack_.insert(element).second) {
            checker_->ThrowTypeError(list, pos);
        }
    }

    explicit TypeStackElement(Checker *checker, void *element, std::string_view err, const lexer::SourcePosition &pos)
        : checker_(checker), element_(element)
    {
        if (!checker->typeStack_.insert(element).second) {
            checker_->ThrowTypeError(err, pos);
        }
    }

    ~TypeStackElement()
    {
        checker_->typeStack_.erase(element_);
    }

    NO_COPY_SEMANTIC(TypeStackElement);
    NO_MOVE_SEMANTIC(TypeStackElement);

private:
    Checker *checker_;
    void *element_;
};

class ScopeContext {
public:
    explicit ScopeContext(Checker *checker, varbinder::Scope *newScope)
        : checker_(checker), prevScope_(checker_->scope_)
    {
        checker_->scope_ = newScope;
    }

    ~ScopeContext()
    {
        checker_->scope_ = prevScope_;
    }

    NO_COPY_SEMANTIC(ScopeContext);
    NO_MOVE_SEMANTIC(ScopeContext);

private:
    Checker *checker_;
    varbinder::Scope *prevScope_;
};

class SavedCheckerContext {
public:
    explicit SavedCheckerContext(Checker *checker, CheckerStatus newStatus)
        : SavedCheckerContext(checker, newStatus, nullptr)
    {
    }

    explicit SavedCheckerContext(Checker *checker, CheckerStatus newStatus, ETSObjectType *containingClass)
        : SavedCheckerContext(checker, newStatus, containingClass, nullptr)
    {
    }

    explicit SavedCheckerContext(Checker *checker, CheckerStatus newStatus, ETSObjectType *containingClass,
                                 Signature *containingSignature)
        : checker_(checker), prev_(checker->context_)
    {
        checker_->context_ = CheckerContext(checker->Allocator(), newStatus, containingClass, containingSignature);
    }

    NO_COPY_SEMANTIC(SavedCheckerContext);
    DEFAULT_MOVE_SEMANTIC(SavedCheckerContext);

    ~SavedCheckerContext()
    {
        checker_->context_ = prev_;
    }

private:
    Checker *checker_;
    CheckerContext prev_;
};

}  // namespace panda::es2panda::checker

#endif /* CHECKER_H */
