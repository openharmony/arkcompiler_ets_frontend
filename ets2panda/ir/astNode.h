/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ir/astNodeMapping.h"
#include "lexer/token/sourceLocation.h"
#include "util/enumbitops.h"

#include <functional>
#include "macros.h"

namespace panda::es2panda::compiler {
class PandaGen;
class ETSGen;
}  // namespace panda::es2panda::compiler

namespace panda::es2panda::checker {
class TSChecker;
class ETSChecker;
class Type;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class AstNode;
class TypeNode;

using NodeTraverser = std::function<void(AstNode *)>;

enum class AstNodeType {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_NODE_TYPES(nodeType, className) nodeType,
    AST_NODE_MAPPING(DECLARE_NODE_TYPES)
#undef DECLARE_NODE_TYPES
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_NODE_TYPES(nodeType1, nodeType2, baseClass, reinterpretClass) nodeType1, nodeType2,
        AST_NODE_REINTERPRET_MAPPING(DECLARE_NODE_TYPES)
#undef DECLARE_NODE_TYPES
};

enum class AstNodeFlags {
    NO_OPTS = 0,
    STRICT = (1U << 0U),
    PARAMETER = (1U << 1U),
};

DEFINE_BITOPS(AstNodeFlags)

enum class ModifierFlags : uint32_t {
    NONE = 0U,
    STATIC = 1U << 0U,
    ASYNC = 1U << 1U,
    PUBLIC = 1U << 2U,
    PROTECTED = 1U << 3U,
    PRIVATE = 1U << 4U,
    DECLARE = 1U << 5U,
    READONLY = 1U << 6U,
    OPTIONAL = 1U << 7U,
    DEFINITE = 1U << 8U,
    ABSTRACT = 1U << 9U,
    CONST = 1U << 10U,
    FINAL = 1U << 11U,
    NATIVE = 1U << 12U,
    OVERRIDE = 1U << 13U,
    CONSTRUCTOR = 1U << 14U,
    SYNCHRONIZED = 1U << 15U,
    FUNCTIONAL = 1U << 16U,
    IN = 1U << 17U,
    OUT = 1U << 18U,
    INTERNAL = 1U << 19U,
    NULLABLE = 1U << 20U,
    EXPORT = 1U << 21U,
    SETTER = 1U << 22U,
    DEFAULT_EXPORT = 1U << 23U,
    ACCESS = PUBLIC | PROTECTED | PRIVATE | INTERNAL,
    ALL = STATIC | ASYNC | ACCESS | DECLARE | READONLY | ABSTRACT,
    ALLOWED_IN_CTOR_PARAMETER = ACCESS | READONLY,
    INTERNAL_PROTECTED = INTERNAL | PROTECTED,
    ACCESSOR_MODIFIERS = ABSTRACT | STATIC | FINAL | OVERRIDE
};

DEFINE_BITOPS(ModifierFlags)

enum class PrivateFieldKind { FIELD, METHOD, GET, SET, STATIC_FIELD, STATIC_METHOD, STATIC_GET, STATIC_SET };

enum class ScriptFunctionFlags : uint32_t {
    NONE = 0U,
    GENERATOR = 1U << 0U,
    ASYNC = 1U << 1U,
    ARROW = 1U << 2U,
    EXPRESSION = 1U << 3U,
    OVERLOAD = 1U << 4U,
    CONSTRUCTOR = 1U << 5U,
    METHOD = 1U << 6U,
    STATIC_BLOCK = 1U << 7U,
    HIDDEN = 1U << 8U,
    IMPLICIT_SUPER_CALL_NEEDED = 1U << 9U,
    ENUM = 1U << 10U,
    EXTERNAL = 1U << 11U,
    PROXY = 1U << 12U,
    THROWS = 1U << 13U,
    RETHROWS = 1U << 14U,
    GETTER = 1U << 15U,
    SETTER = 1U << 16U,
    DEFAULT_PARAM_PROXY = 1U << 17U,
    ENTRY_POINT = 1U << 18U
};

DEFINE_BITOPS(ScriptFunctionFlags)

enum class TSOperatorType { READONLY, KEYOF, UNIQUE };
enum class MappedOption { NO_OPTS, PLUS, MINUS };

enum class BoxingUnboxingFlags : uint32_t {
    NONE = 0U,
    BOX_TO_BOOLEAN = 1U << 0U,
    BOX_TO_BYTE = 1U << 1U,
    BOX_TO_SHORT = 1U << 2U,
    BOX_TO_CHAR = 1U << 3U,
    BOX_TO_INT = 1U << 4U,
    BOX_TO_LONG = 1U << 5U,
    BOX_TO_FLOAT = 1U << 6U,
    BOX_TO_DOUBLE = 1U << 7U,
    UNBOX_TO_BOOLEAN = 1U << 8U,
    UNBOX_TO_BYTE = 1U << 9U,
    UNBOX_TO_SHORT = 1U << 10U,
    UNBOX_TO_CHAR = 1U << 11U,
    UNBOX_TO_INT = 1U << 12U,
    UNBOX_TO_LONG = 1U << 13U,
    UNBOX_TO_FLOAT = 1U << 14U,
    UNBOX_TO_DOUBLE = 1U << 15U,
    BOXING_FLAG = BOX_TO_BOOLEAN | BOX_TO_BYTE | BOX_TO_SHORT | BOX_TO_CHAR | BOX_TO_INT | BOX_TO_LONG | BOX_TO_FLOAT |
                  BOX_TO_DOUBLE,
    UNBOXING_FLAG = UNBOX_TO_BOOLEAN | UNBOX_TO_BYTE | UNBOX_TO_SHORT | UNBOX_TO_CHAR | UNBOX_TO_INT | UNBOX_TO_LONG |
                    UNBOX_TO_FLOAT | UNBOX_TO_DOUBLE,

};

DEFINE_BITOPS(BoxingUnboxingFlags)

// Forward declarations
class AstDumper;
class Expression;
class Statement;
class ClassElement;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(nodeType, className) class className;
AST_NODE_MAPPING(DECLARE_CLASSES)
#undef DECLARE_CLASSES

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(nodeType1, nodeType2, baseClass, reinterpretClass) class baseClass;
AST_NODE_REINTERPRET_MAPPING(DECLARE_CLASSES)
#undef DECLARE_CLASSES

class AstNode {
public:
    explicit AstNode(AstNodeType type) : type_(type) {};
    explicit AstNode(AstNodeType type, ModifierFlags flags) : type_(type), flags_(flags) {};
    virtual ~AstNode() = default;
    NO_COPY_SEMANTIC(AstNode);
    NO_MOVE_SEMANTIC(AstNode);

    bool IsProgram() const
    {
        return parent_ == nullptr;
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_IS_CHECKS(nodeType, className) \
    bool Is##className() const                 \
    {                                          \
        return type_ == AstNodeType::nodeType; \
    }
    AST_NODE_MAPPING(DECLARE_IS_CHECKS)
#undef DECLARE_IS_CHECKS

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_IS_CHECKS(nodeType1, nodeType2, baseClass, reinterpretClass) \
    bool Is##baseClass() const                                               \
    {                                                                        \
        return type_ == AstNodeType::nodeType1;                              \
    }                                                                        \
    bool Is##reinterpretClass() const                                        \
    {                                                                        \
        return type_ == AstNodeType::nodeType2;                              \
    }
    AST_NODE_REINTERPRET_MAPPING(DECLARE_IS_CHECKS)
#undef DECLARE_IS_CHECKS

    virtual bool IsStatement() const
    {
        return false;
    }

    virtual bool IsExpression() const
    {
        return false;
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AS_CASTS(nodeType, className)             \
    className *As##className()                            \
    {                                                     \
        ASSERT(Is##className());                          \
        return reinterpret_cast<className *>(this);       \
    }                                                     \
    const className *As##className() const                \
    {                                                     \
        ASSERT(Is##className());                          \
        return reinterpret_cast<const className *>(this); \
    }
    AST_NODE_MAPPING(DECLARE_AS_CASTS)
#undef DECLARE_AS_CASTS

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_AS_CASTS(nodeType1, nodeType2, baseClass, reinterpretClass) \
    baseClass *As##baseClass()                                              \
    {                                                                       \
        ASSERT(Is##baseClass());                                            \
        return reinterpret_cast<baseClass *>(this);                         \
    }                                                                       \
    baseClass *As##reinterpretClass()                                       \
    {                                                                       \
        ASSERT(Is##reinterpretClass());                                     \
        return reinterpret_cast<baseClass *>(this);                         \
    }                                                                       \
    const baseClass *As##baseClass() const                                  \
    {                                                                       \
        ASSERT(Is##baseClass());                                            \
        return reinterpret_cast<const baseClass *>(this);                   \
    }                                                                       \
    const baseClass *As##reinterpretClass() const                           \
    {                                                                       \
        ASSERT(Is##reinterpretClass());                                     \
        return reinterpret_cast<const baseClass *>(this);                   \
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

    void SetRange(const lexer::SourceRange &loc)
    {
        range_ = loc;
    }

    void SetStart(const lexer::SourcePosition &start)
    {
        range_.start = start;
    }

    void SetEnd(const lexer::SourcePosition &end)
    {
        range_.end = end;
    }

    const lexer::SourcePosition &Start() const
    {
        return range_.start;
    }

    const lexer::SourcePosition &End() const
    {
        return range_.end;
    }

    const lexer::SourceRange &Range() const
    {
        return range_;
    }

    AstNodeType Type() const
    {
        return type_;
    }

    AstNode *Parent()
    {
        return parent_;
    }

    const AstNode *Parent() const
    {
        return parent_;
    }

    void SetParent(AstNode *parent)
    {
        parent_ = parent;
    }

    binder::Variable *Variable() const
    {
        return variable_;
    }

    void SetVariable(binder::Variable *variable)
    {
        variable_ = variable;
    }

    virtual void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators)
    {
        UNREACHABLE();
    }

    virtual bool CanHaveDecorator([[maybe_unused]] bool in_ts) const
    {
        return false;
    }

    bool IsReadonly() const
    {
        return (flags_ & ModifierFlags::READONLY) != 0;
    }

    bool IsOptional() const
    {
        return (flags_ & ModifierFlags::OPTIONAL) != 0;
    }

    bool IsDefinite() const
    {
        return (flags_ & ModifierFlags::DEFINITE) != 0;
    }

    bool IsConstructor() const
    {
        return (flags_ & ModifierFlags::CONSTRUCTOR) != 0;
    }

    bool IsOverride() const
    {
        return (flags_ & ModifierFlags::OVERRIDE) != 0;
    }

    bool IsAsync() const
    {
        return (flags_ & ModifierFlags::ASYNC) != 0;
    }

    bool IsSynchronized() const
    {
        return (flags_ & ModifierFlags::SYNCHRONIZED) != 0;
    }

    bool IsNative() const
    {
        return (flags_ & ModifierFlags::NATIVE) != 0;
    }

    bool IsNullable() const
    {
        return (flags_ & ModifierFlags::NULLABLE) != 0;
    }

    bool IsConst() const
    {
        return (flags_ & ModifierFlags::CONST) != 0;
    }

    bool IsStatic() const
    {
        return (flags_ & ModifierFlags::STATIC) != 0;
    }

    bool IsFinal() const noexcept
    {
        return (flags_ & ModifierFlags::FINAL) != 0U;
    }

    bool IsAbstract() const
    {
        return (flags_ & ModifierFlags::ABSTRACT) != 0;
    }

    bool IsPublic() const
    {
        return (flags_ & ModifierFlags::PUBLIC) != 0;
    }

    bool IsProtected() const
    {
        return (flags_ & ModifierFlags::PROTECTED) != 0;
    }

    bool IsPrivate() const
    {
        return (flags_ & ModifierFlags::PRIVATE) != 0;
    }

    bool IsInternal() const
    {
        return (flags_ & ModifierFlags::INTERNAL) != 0;
    }

    bool IsExported() const
    {
        return (flags_ & ModifierFlags::EXPORT) != 0;
    }

    bool IsDefaultExported() const
    {
        return (flags_ & ModifierFlags::DEFAULT_EXPORT) != 0;
    }

    bool IsDeclare() const
    {
        return (flags_ & ModifierFlags::DECLARE) != 0;
    }

    bool IsIn() const
    {
        return (flags_ & ModifierFlags::IN) != 0;
    }

    bool IsOut() const
    {
        return (flags_ & ModifierFlags::OUT) != 0;
    }

    bool IsSetter() const
    {
        return (flags_ & ModifierFlags::SETTER) != 0;
    }

    void AddModifier(ModifierFlags flags)
    {
        flags_ |= flags;
    }

    ModifierFlags Modifiers()
    {
        return flags_;
    }

    ModifierFlags Modifiers() const
    {
        return flags_;
    }

    void SetBoxingUnboxingFlags(BoxingUnboxingFlags flags) const
    {
        boxing_unboxing_flags_ = flags;
    }

    void AddBoxingUnboxingFlag(BoxingUnboxingFlags flag) const
    {
        boxing_unboxing_flags_ |= flag;
    }

    BoxingUnboxingFlags GetBoxingUnboxingFlags() const
    {
        return boxing_unboxing_flags_;
    }

    ir::ClassElement *AsClassElement()
    {
        ASSERT(IsMethodDefinition() || IsClassProperty() || IsClassStaticBlock());
        return reinterpret_cast<ir::ClassElement *>(this);
    }

    const ir::ClassElement *AsClassElement() const
    {
        ASSERT(IsMethodDefinition() || IsClassProperty() || IsClassStaticBlock());
        return reinterpret_cast<const ir::ClassElement *>(this);
    }

    ir::BlockStatement *GetTopStatement();
    const ir::BlockStatement *GetTopStatement() const;

    virtual void Iterate(const NodeTraverser &cb) const = 0;
    virtual void Dump(ir::AstDumper *dumper) const = 0;
    virtual void Compile([[maybe_unused]] compiler::PandaGen *pg) const = 0;
    virtual void Compile([[maybe_unused]] compiler::ETSGen *etsg) const {};
    virtual checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) = 0;
    virtual checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) = 0;

protected:
    void SetType(AstNodeType type)
    {
        type_ = type;
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    AstNode *parent_ {};
    lexer::SourceRange range_ {};
    AstNodeType type_;
    binder::Variable *variable_ {};
    ModifierFlags flags_ {};
    mutable BoxingUnboxingFlags boxing_unboxing_flags_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

template <typename T>
class Typed : public T {
public:
    checker::Type *TsType()
    {
        return ts_type_;
    }

    const checker::Type *TsType() const
    {
        return ts_type_;
    }

    void SetTsType(checker::Type *ts_type)
    {
        ts_type_ = ts_type;
    }

protected:
    explicit Typed(AstNodeType type) : T(type) {}
    explicit Typed(AstNodeType type, ModifierFlags flags) : T(type, flags) {}

private:
    checker::Type *ts_type_ {};
};

template <typename T>
class Annotated : public T {
public:
    TypeNode *TypeAnnotation() const
    {
        return type_annotation_;
    }

    void SetTsTypeAnnotation(TypeNode *type_annotation)
    {
        type_annotation_ = type_annotation;
    }

protected:
    explicit Annotated(AstNodeType type, TypeNode *type_annotation) : T(type), type_annotation_(type_annotation) {}
    explicit Annotated(AstNodeType type) : T(type) {}
    explicit Annotated(AstNodeType type, ModifierFlags flags) : T(type, flags) {}

private:
    TypeNode *type_annotation_ {};
};

class TypedAstNode : public Typed<AstNode> {
protected:
    explicit TypedAstNode(AstNodeType type) : Typed<AstNode>(type) {};
    explicit TypedAstNode(AstNodeType type, ModifierFlags flags) : Typed<AstNode>(type, flags) {};
};

class AnnotatedAstNode : public Annotated<AstNode> {
protected:
    explicit AnnotatedAstNode(AstNodeType type, TypeNode *type_annotation) : Annotated<AstNode>(type, type_annotation)
    {
    }
    explicit AnnotatedAstNode(AstNodeType type) : Annotated<AstNode>(type) {}
    explicit AnnotatedAstNode(AstNodeType type, ModifierFlags flags) : Annotated<AstNode>(type, flags) {}
};
}  // namespace panda::es2panda::ir
#endif
