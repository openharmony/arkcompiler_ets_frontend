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

#ifndef ES2PANDA_COMPILER_SCOPES_DECLARATION_H
#define ES2PANDA_COMPILER_SCOPES_DECLARATION_H

#include "binder/variableFlags.h"
#include "macros.h"
#include "util/ustring.h"

namespace panda::es2panda::ir {
class AstNode;
class ScriptFunction;
class TSInterfaceDeclaration;
class ImportDeclaration;
class ETSImportDeclaration;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::binder {
class Scope;
class LocalScope;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(decl_kind, className) class className;
DECLARATION_KINDS(DECLARE_CLASSES)
#undef DECLARE_CLASSES

class Decl {
public:
    virtual ~Decl() = default;
    NO_COPY_SEMANTIC(Decl);
    NO_MOVE_SEMANTIC(Decl);

    virtual DeclType Type() const = 0;

    const util::StringView &Name() const
    {
        return name_;
    }

    ir::AstNode *Node()
    {
        return node_;
    }

    const ir::AstNode *Node() const
    {
        return node_;
    }

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CHECKS_CASTS(declKind, className)         \
    bool Is##className() const                            \
    {                                                     \
        return Type() == DeclType::declKind;              \
    }                                                     \
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
    DECLARATION_KINDS(DECLARE_CHECKS_CASTS)
#undef DECLARE_CHECKS_CASTS

    void BindNode(ir::AstNode *node)
    {
        node_ = node;
    }

    bool IsLetOrConstDecl() const
    {
        return IsLetDecl() || IsConstDecl();
    }

    bool PossibleTDZ() const
    {
        return IsLetOrConstDecl() || IsParameterDecl();
    }

protected:
    explicit Decl(util::StringView name) : name_(name) {}
    explicit Decl(util::StringView name, ir::AstNode *decl_node) : name_(name), node_(decl_node) {}

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    util::StringView name_;
    ir::AstNode *node_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

template <typename T>
class MultiDecl : public Decl {
public:
    explicit MultiDecl(ArenaAllocator *allocator, util::StringView name)
        : Decl(name), declarations_(allocator->Adapter())
    {
    }

    explicit MultiDecl(ArenaAllocator *allocator, util::StringView name, ir::AstNode *decl_node)
        : Decl(name, decl_node), declarations_(allocator->Adapter())
    {
    }

    const ArenaVector<T *> &Decls() const
    {
        return declarations_;
    }

    void Add(T *decl)
    {
        declarations_.push_back(decl);
    }

private:
    ArenaVector<T *> declarations_;
};

class EnumLiteralDecl : public Decl {
public:
    explicit EnumLiteralDecl(util::StringView name, bool is_const) : Decl(name), is_const_(is_const) {}
    explicit EnumLiteralDecl(util::StringView name, ir::AstNode *decl_node, bool is_const)
        : Decl(name, decl_node), is_const_(is_const)
    {
    }

    DeclType Type() const override
    {
        return DeclType::ENUM_LITERAL;
    }

    bool IsConst() const
    {
        return is_const_;
    }

    void BindScope(LocalScope *scope)
    {
        scope_ = scope;
    }

    LocalScope *Scope()
    {
        return scope_;
    }

private:
    LocalScope *scope_ {};
    bool is_const_ {};
};

class InterfaceDecl : public MultiDecl<ir::TSInterfaceDeclaration> {
public:
    explicit InterfaceDecl(ArenaAllocator *allocator, util::StringView name) : MultiDecl(allocator, name) {}
    explicit InterfaceDecl(ArenaAllocator *allocator, util::StringView name, ir::AstNode *decl_node)
        : MultiDecl(allocator, name, decl_node)
    {
    }

    DeclType Type() const override
    {
        return DeclType::INTERFACE;
    }
};

class ClassDecl : public Decl {
public:
    explicit ClassDecl(util::StringView name) : Decl(name) {}
    explicit ClassDecl(util::StringView name, ir::AstNode *node) : Decl(name, node) {}

    DeclType Type() const override
    {
        return DeclType::CLASS;
    }
};

class FunctionDecl : public MultiDecl<ir::ScriptFunction> {
public:
    explicit FunctionDecl(ArenaAllocator *allocator, util::StringView name, ir::AstNode *node)
        : MultiDecl(allocator, name)
    {
        node_ = node;
    }

    DeclType Type() const override
    {
        return DeclType::FUNC;
    }
};

class TypeParameterDecl : public Decl {
public:
    explicit TypeParameterDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::TYPE_PARAMETER;
    }
};

class PropertyDecl : public Decl {
public:
    explicit PropertyDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::PROPERTY;
    }
};

class MethodDecl : public Decl {
public:
    explicit MethodDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::METHOD;
    }
};

class EnumDecl : public Decl {
public:
    explicit EnumDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::ENUM;
    }
};

class TypeAliasDecl : public Decl {
public:
    explicit TypeAliasDecl(util::StringView name) : Decl(name) {}
    explicit TypeAliasDecl(util::StringView name, ir::AstNode *node) : Decl(name, node) {}

    DeclType Type() const override
    {
        return DeclType::TYPE_ALIAS;
    }
};

class NameSpaceDecl : public Decl {
public:
    explicit NameSpaceDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::NAMESPACE;
    }
};

class VarDecl : public Decl {
public:
    explicit VarDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::VAR;
    }
};

class LetDecl : public Decl {
public:
    explicit LetDecl(util::StringView name) : Decl(name) {}
    explicit LetDecl(util::StringView name, ir::AstNode *decl_node) : Decl(name, decl_node) {}

    DeclType Type() const override
    {
        return DeclType::LET;
    }
};

class ConstDecl : public Decl {
public:
    explicit ConstDecl(util::StringView name) : Decl(name) {}
    explicit ConstDecl(util::StringView name, ir::AstNode *decl_node) : Decl(name, decl_node) {}

    DeclType Type() const override
    {
        return DeclType::CONST;
    }
};

class ParameterDecl : public Decl {
public:
    explicit ParameterDecl(util::StringView name) : Decl(name) {}

    DeclType Type() const override
    {
        return DeclType::PARAM;
    }
};

class ImportDecl : public Decl {
public:
    explicit ImportDecl(util::StringView import_name, util::StringView local_name)
        : Decl(local_name), import_name_(import_name)
    {
    }

    explicit ImportDecl(util::StringView import_name, util::StringView local_name, ir::AstNode *node)
        : Decl(local_name), import_name_(import_name)
    {
        BindNode(node);
    }

    const util::StringView &ImportName() const
    {
        return import_name_;
    }

    const util::StringView &LocalName() const
    {
        return name_;
    }

    DeclType Type() const override
    {
        return DeclType::IMPORT;
    }

private:
    util::StringView import_name_;
};

class ExportDecl : public Decl {
public:
    explicit ExportDecl(util::StringView export_name, util::StringView local_name)
        : Decl(local_name), export_name_(export_name)
    {
    }

    explicit ExportDecl(util::StringView export_name, util::StringView local_name, ir::AstNode *node)
        : Decl(local_name), export_name_(export_name)
    {
        BindNode(node);
    }

    const util::StringView &ExportName() const
    {
        return export_name_;
    }

    const util::StringView &LocalName() const
    {
        return name_;
    }

    DeclType Type() const override
    {
        return DeclType::EXPORT;
    }

private:
    util::StringView export_name_;
};
}  // namespace panda::es2panda::binder

#endif
