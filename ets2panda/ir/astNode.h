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

#ifndef ES2PANDA_IR_AST_NODE_H
#define ES2PANDA_IR_AST_NODE_H

#include "astNodeFlags.h"
#include "astNodeMapping.h"
#include "ir/visitor/AstVisitor.h"
#include "lexer/token/sourceLocation.h"
#include "macros.h"

namespace ark::es2panda::compiler {
class PandaGen;
class ETSGen;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::checker {
class TSChecker;
class ETSChecker;
class Type;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::varbinder {
class Variable;
class Scope;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::ir {
// NOLINTBEGIN(modernize-avoid-c-arrays)
inline constexpr char const CLONE_ALLOCATION_ERROR[] = "Unsuccessful allocation during cloning.";
// NOLINTEND(modernize-avoid-c-arrays)

class AstNode;
class TypeNode;

using NodeTransformer = std::function<AstNode *(AstNode *)>;
using NodeTraverser = std::function<void(AstNode *)>;
using NodePredicate = std::function<bool(AstNode *)>;

enum class AstNodeType {
/* CC-OFFNXT(G.PRE.02,G.PRE.09) name part*/
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_NODE_TYPES(nodeType, className) nodeType,
    AST_NODE_MAPPING(DECLARE_NODE_TYPES)
#undef DECLARE_NODE_TYPES
/* CC-OFFNXT(G.PRE.02,G.PRE.09) name part*/
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_NODE_TYPES(nodeType1, nodeType2, baseClass, reinterpretClass) nodeType1, nodeType2,
        AST_NODE_REINTERPRET_MAPPING(DECLARE_NODE_TYPES)
#undef DECLARE_NODE_TYPES
};

// Forward declarations
class AstDumper;
class Expression;
class SrcDumper;
class Statement;
class ClassElement;
template <typename T>
class Typed;

/* CC-OFFNXT(G.PRE.02) name part*/
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(nodeType, className) class className; /* CC-OFF(G.PRE.09) code gen*/
AST_NODE_MAPPING(DECLARE_CLASSES)
#undef DECLARE_CLASSES

/* CC-OFFNXT(G.PRE.02,G.PRE.09) name part code gen*/
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(nodeType1, nodeType2, baseClass, reinterpretClass) class baseClass;
AST_NODE_REINTERPRET_MAPPING(DECLARE_CLASSES)
#undef DECLARE_CLASSES

class AstNode {
public:
    explicit AstNode(AstNodeType type) : type_(type) {};
    explicit AstNode(AstNodeType type, ModifierFlags flags) : type_(type), flags_(flags) {};
    virtual ~AstNode() = default;

    AstNode() = delete;
    NO_MOVE_SEMANTIC(AstNode);

    bool IsProgram() const
    {
        return parent_ == nullptr;
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_IS_CHECKS(nodeType, className)                                               \
    bool Is##className() const                                                               \
    {                                                                                        \
        /* CC-OFFNXT(G.PRE.02) name part*/                                                   \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed */ \
        return type_ == AstNodeType::nodeType; /* CC-OFF(G.PRE.02) name part*/               \
    }
    AST_NODE_MAPPING(DECLARE_IS_CHECKS)
#undef DECLARE_IS_CHECKS

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_IS_CHECKS(nodeType1, nodeType2, baseClass, reinterpretClass)                 \
    bool Is##baseClass() const                                                               \
    {                                                                                        \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed */ \
        return type_ == AstNodeType::nodeType1; /* CC-OFF(G.PRE.02) name part*/              \
    }                                                                                        \
    bool Is##reinterpretClass() const                                                        \
    {                                                                                        \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed */ \
        return type_ == AstNodeType::nodeType2; /* CC-OFF(G.PRE.02) name part*/              \
    }
    AST_NODE_REINTERPRET_MAPPING(DECLARE_IS_CHECKS)
#undef DECLARE_IS_CHECKS

    [[nodiscard]] virtual bool IsStatement() const noexcept
    {
        return false;
    }

    [[nodiscard]] virtual bool IsExpression() const noexcept
    {
        return false;
    }

    virtual bool IsTyped() const
    {
        return false;
    }

    Typed<AstNode> *AsTyped()
    {
        ASSERT(IsTyped());
        return reinterpret_cast<Typed<AstNode> *>(this);
    }

    Typed<AstNode> const *AsTyped() const
    {
        ASSERT(IsTyped());
        return reinterpret_cast<Typed<AstNode> const *>(this);
    }

/* CC-OFFNXT(G.PRE.06) solid logic */
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AS_CASTS(nodeType, className)                                                         \
    /* CC-OFFNXT(G.PRE.02) name part*/                                                                \
    className *As##className()                                                                        \
    {                                                                                                 \
        ASSERT(Is##className());                                                                      \
        /* CC-OFFNXT(G.PRE.05,G.PRE.02) The macro is used to generate a function. Return is needed */ \
        return reinterpret_cast<className *>(this);                                                   \
    }                                                                                                 \
    const className *As##className() const                                                            \
    {                                                                                                 \
        ASSERT(Is##className());                                                                      \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed */          \
        return reinterpret_cast<const className *>(this);                                             \
    }
    AST_NODE_MAPPING(DECLARE_AS_CASTS)
#undef DECLARE_AS_CASTS

/* CC-OFFNXT(G.PRE.06) solid logic */
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AS_CASTS(nodeType1, nodeType2, baseClass, reinterpretClass)                           \
    /* CC-OFFNXT(G.PRE.02) name part*/                                                                \
    baseClass *As##baseClass()                                                                        \
    {                                                                                                 \
        ASSERT(Is##baseClass());                                                                      \
        /* CC-OFFNXT(G.PRE.05,G.PRE.02) The macro is used to generate a function. Return is needed */ \
        return reinterpret_cast<baseClass *>(this);                                                   \
    }                                                                                                 \
    /* CC-OFFNXT(G.PRE.02) name part*/                                                                \
    baseClass *As##reinterpretClass()                                                                 \
    {                                                                                                 \
        ASSERT(Is##reinterpretClass());                                                               \
        /* CC-OFFNXT(G.PRE.05,G.PRE.02) The macro is used to generate a function. Return is needed */ \
        return reinterpret_cast<baseClass *>(this);                                                   \
    }                                                                                                 \
    const baseClass *As##baseClass() const                                                            \
    {                                                                                                 \
        ASSERT(Is##baseClass());                                                                      \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed */          \
        return reinterpret_cast<const baseClass *>(this);                                             \
    }                                                                                                 \
    const baseClass *As##reinterpretClass() const                                                     \
    {                                                                                                 \
        ASSERT(Is##reinterpretClass());                                                               \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed */          \
        return reinterpret_cast<const baseClass *>(this);                                             \
    }
    AST_NODE_REINTERPRET_MAPPING(DECLARE_AS_CASTS)
#undef DECLARE_AS_CASTS

    Expression *AsExpression()
    {
        ASSERT(IsExpression());
        return reinterpret_cast<Expression *>(this);
    }

    const Expression *AsExpression() const
    {
        ASSERT(IsExpression());
        return reinterpret_cast<const Expression *>(this);
    }

    Statement *AsStatement()
    {
        ASSERT(IsStatement());
        return reinterpret_cast<Statement *>(this);
    }

    const Statement *AsStatement() const
    {
        ASSERT(IsStatement());
        return reinterpret_cast<const Statement *>(this);
    }

    void SetRange(const lexer::SourceRange &loc) noexcept
    {
        range_ = loc;
    }

    void SetStart(const lexer::SourcePosition &start) noexcept
    {
        range_.start = start;
    }

    void SetEnd(const lexer::SourcePosition &end) noexcept
    {
        range_.end = end;
    }

    [[nodiscard]] const lexer::SourcePosition &Start() const noexcept
    {
        return range_.start;
    }

    [[nodiscard]] const lexer::SourcePosition &End() const noexcept
    {
        return range_.end;
    }

    [[nodiscard]] const lexer::SourceRange &Range() const noexcept
    {
        return range_;
    }

    [[nodiscard]] AstNodeType Type() const noexcept
    {
        return type_;
    }

    [[nodiscard]] AstNode *Parent() noexcept
    {
        return parent_;
    }

    [[nodiscard]] const AstNode *Parent() const noexcept
    {
        return parent_;
    }

    void SetParent(AstNode *const parent) noexcept
    {
        parent_ = parent;
    }

    [[nodiscard]] varbinder::Variable *Variable() const noexcept
    {
        return variable_;
    }

    void SetVariable(varbinder::Variable *variable) noexcept
    {
        variable_ = variable;
    }

    // When no decorators are allowed, we cannot return a reference to an empty vector.
    virtual const ArenaVector<ir::Decorator *> *DecoratorsPtr() const
    {
        return nullptr;
    }

    virtual void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators)
    {
        UNREACHABLE();
    }

    virtual bool CanHaveDecorator([[maybe_unused]] bool inTs) const
    {
        return false;
    }

    [[nodiscard]] bool IsReadonly() const noexcept
    {
        return (flags_ & ModifierFlags::READONLY) != 0;
    }

    // NOTE: For readonly parameter type
    [[nodiscard]] bool IsReadonlyType() const noexcept
    {
        return (flags_ & ModifierFlags::READONLY_PARAMETER) != 0;
    }

    [[nodiscard]] bool IsOptionalDeclaration() const noexcept
    {
        return (flags_ & ModifierFlags::OPTIONAL) != 0;
    }

    [[nodiscard]] bool IsDefinite() const noexcept
    {
        return (flags_ & ModifierFlags::DEFINITE) != 0;
    }

    [[nodiscard]] bool IsConstructor() const noexcept
    {
        return (flags_ & ModifierFlags::CONSTRUCTOR) != 0;
    }

    [[nodiscard]] bool IsOverride() const noexcept
    {
        return (flags_ & ModifierFlags::OVERRIDE) != 0;
    }

    void SetOverride() noexcept
    {
        flags_ |= ModifierFlags::OVERRIDE;
    }

    [[nodiscard]] bool IsAsync() const noexcept
    {
        return (flags_ & ModifierFlags::ASYNC) != 0;
    }

    [[nodiscard]] bool IsSynchronized() const noexcept
    {
        return (flags_ & ModifierFlags::SYNCHRONIZED) != 0;
    }

    [[nodiscard]] bool IsNative() const noexcept
    {
        return (flags_ & ModifierFlags::NATIVE) != 0;
    }

    [[nodiscard]] bool IsConst() const noexcept
    {
        return (flags_ & ModifierFlags::CONST) != 0;
    }

    [[nodiscard]] bool IsStatic() const noexcept
    {
        return (flags_ & ModifierFlags::STATIC) != 0;
    }

    [[nodiscard]] bool IsFinal() const noexcept
    {
        return (flags_ & ModifierFlags::FINAL) != 0U;
    }

    [[nodiscard]] bool IsAbstract() const noexcept
    {
        return (flags_ & ModifierFlags::ABSTRACT) != 0;
    }

    [[nodiscard]] bool IsPublic() const noexcept
    {
        return (flags_ & ModifierFlags::PUBLIC) != 0;
    }

    [[nodiscard]] bool IsProtected() const noexcept
    {
        return (flags_ & ModifierFlags::PROTECTED) != 0;
    }

    [[nodiscard]] bool IsPrivate() const noexcept
    {
        return (flags_ & ModifierFlags::PRIVATE) != 0;
    }

    [[nodiscard]] bool IsInternal() const noexcept
    {
        return (flags_ & ModifierFlags::INTERNAL) != 0;
    }

    [[nodiscard]] bool IsExported() const noexcept;

    [[nodiscard]] bool IsDefaultExported() const noexcept;

    [[nodiscard]] bool IsExportedType() const noexcept;

    [[nodiscard]] bool IsDeclare() const noexcept
    {
        return (flags_ & ModifierFlags::DECLARE) != 0;
    }

    [[nodiscard]] bool IsIn() const noexcept
    {
        return (flags_ & ModifierFlags::IN) != 0;
    }

    [[nodiscard]] bool IsOut() const noexcept
    {
        return (flags_ & ModifierFlags::OUT) != 0;
    }

    [[nodiscard]] bool IsSetter() const noexcept
    {
        return (flags_ & ModifierFlags::SETTER) != 0;
    }

    void AddModifier(ModifierFlags const flags) noexcept
    {
        flags_ |= flags;
    }

    void ClearModifier(ModifierFlags const flags) noexcept
    {
        flags_ &= ~flags;
    }

    [[nodiscard]] ModifierFlags Modifiers() noexcept
    {
        return flags_;
    }

    [[nodiscard]] ModifierFlags Modifiers() const noexcept
    {
        return flags_;
    }

    [[nodiscard]] bool HasExportAlias() const noexcept;
    // CC-OFFNXT(G.PRE.06) solid logic
    // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_FLAG_OPERATIONS(flag_type, member_name)                                     \
    void Set##flag_type(flag_type flags) const noexcept                                     \
    {                                                                                       \
        (member_name) = flags;                                                              \
    }                                                                                       \
                                                                                            \
    void Add##flag_type(flag_type flag) const noexcept                                      \
    {                                                                                       \
        (member_name) |= flag;                                                              \
    }                                                                                       \
                                                                                            \
    [[nodiscard]] flag_type Get##flag_type() const noexcept                                 \
    {                                                                                       \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed*/ \
        return (member_name);                                                               \
    }                                                                                       \
                                                                                            \
    bool Has##flag_type(flag_type flag) const noexcept                                      \
    {                                                                                       \
        /* CC-OFFNXT(G.PRE.05) The macro is used to generate a function. Return is needed*/ \
        return ((member_name)&flag) != 0U;                                                  \
    }                                                                                       \
    void Remove##flag_type(flag_type flag) const noexcept                                   \
    {                                                                                       \
        (member_name) &= ~flag;                                                             \
    }

    DECLARE_FLAG_OPERATIONS(BoxingUnboxingFlags, boxingUnboxingFlags_);
    DECLARE_FLAG_OPERATIONS(AstNodeFlags, astNodeFlags_);
#undef DECLARE_FLAG_OPERATIONS

    ir::ClassElement *AsClassElement();
    const ir::ClassElement *AsClassElement() const;

    static varbinder::Scope *EnclosingScope(const ir::AstNode *expr);

    [[nodiscard]] virtual bool IsScopeBearer() const noexcept;
    [[nodiscard]] virtual varbinder::Scope *Scope() const noexcept;

    virtual void ClearScope() noexcept;

    [[nodiscard]] ir::BlockStatement *GetTopStatement();
    [[nodiscard]] const ir::BlockStatement *GetTopStatement() const;

    [[nodiscard]] virtual AstNode *Clone(ArenaAllocator *const allocator, AstNode *const parent);

    virtual void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) = 0;
    virtual void Iterate(const NodeTraverser &cb) const = 0;

    void TransformChildrenRecursively(const NodeTransformer &cb, std::string_view transformationName);
    void TransformChildrenRecursivelyPreorder(const NodeTransformer &cb, std::string_view transformationName);
    void TransformChildrenRecursivelyPostorder(const NodeTransformer &cb, std::string_view transformationName);

    void IterateRecursively(const NodeTraverser &cb) const;
    void IterateRecursivelyPreorder(const NodeTraverser &cb) const;
    void IterateRecursivelyPostorder(const NodeTraverser &cb) const;

    bool IsAnyChild(const NodePredicate &cb) const;
    AstNode *FindChild(const NodePredicate &cb) const;

    std::string DumpJSON() const;
    std::string DumpEtsSrc() const;

    virtual void Dump(ir::AstDumper *dumper) const = 0;
    virtual void Dump(ir::SrcDumper *dumper) const = 0;
    virtual void Compile([[maybe_unused]] compiler::PandaGen *pg) const = 0;
    virtual void Compile([[maybe_unused]] compiler::ETSGen *etsg) const {};
    virtual checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) = 0;
    virtual checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) = 0;

    void SetTransformedNode(std::string_view transformationName, AstNode *transformedNode);

    using ASTVisitorT = visitor::ASTAbstractVisitor;

    virtual void Accept(ASTVisitorT *v) = 0;

    /**
     * On each node you should implement:
     *  void accept(AV* v) override {
     *      ASTVisitorT::accept(this, v);
     *  }
     */
    void SetOriginalNode(AstNode *originalNode) noexcept;
    AstNode *OriginalNode() const noexcept;

protected:
    AstNode(AstNode const &other);

    void SetType(AstNodeType const type) noexcept
    {
        type_ = type;
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    AstNode *parent_ {};
    lexer::SourceRange range_ {};
    AstNodeType type_;
    ModifierFlags flags_ {};
    mutable AstNodeFlags astNodeFlags_ {};
    mutable BoxingUnboxingFlags boxingUnboxingFlags_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)

private:
    AstNode &operator=(const AstNode &) = default;

    varbinder::Variable *variable_ {};
    AstNode *originalNode_ = nullptr;
    // {lowering_phase_name, new_generated_node}
    std::optional<std::pair<std::string_view, AstNode *>> transformedNode_ = std::nullopt;
};

template <typename T>
class Annotated : public T {
public:
    Annotated() = delete;
    ~Annotated() override = default;

    Annotated &operator=(const Annotated &) = delete;
    NO_MOVE_SEMANTIC(Annotated);

    [[nodiscard]] TypeNode *TypeAnnotation() const noexcept
    {
        return typeAnnotation_;
    }

    void SetTsTypeAnnotation(TypeNode *const typeAnnotation) noexcept
    {
        typeAnnotation_ = typeAnnotation;
    }

protected:
    explicit Annotated(AstNodeType const type, TypeNode *const typeAnnotation)
        : T(type), typeAnnotation_(typeAnnotation)
    {
    }
    explicit Annotated(AstNodeType const type) : T(type) {}
    explicit Annotated(AstNodeType const type, ModifierFlags const flags) : T(type, flags) {}

    Annotated(Annotated const &other) : T(static_cast<T const &>(other)) {}

private:
    TypeNode *typeAnnotation_ {};
};

}  // namespace ark::es2panda::ir
#endif
