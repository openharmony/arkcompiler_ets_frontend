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

#ifndef ES2PANDA_COMPILER_SCOPES_VARIABLE_H
#define ES2PANDA_COMPILER_SCOPES_VARIABLE_H

#include "plugins/ecmascript/es2panda/binder/enumMemberResult.h"
#include "plugins/ecmascript/es2panda/binder/variableFlags.h"
#include "plugins/ecmascript/es2panda/ir/irnode.h"
#include "macros.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"

#include <limits>

namespace panda::es2panda::checker {
class Type;
enum class PropertyType;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::binder {
class Decl;
class Scope;
class VariableScope;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(type, className) class className;
VARIABLE_TYPES(DECLARE_CLASSES)
#undef DECLARE_CLASSES

class Variable {
public:
    virtual ~Variable() = default;
    NO_COPY_SEMANTIC(Variable);
    NO_MOVE_SEMANTIC(Variable);

    VariableType virtual Type() const = 0;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CHECKS_CASTS(variableType, className)     \
    bool Is##className() const                            \
    {                                                     \
        return Type() == VariableType::variableType;      \
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
    VARIABLE_TYPES(DECLARE_CHECKS_CASTS)
#undef DECLARE_CHECKS_CASTS

    const Decl *Declaration() const
    {
        return decl_;
    }

    Decl *Declaration()
    {
        return decl_;
    }

    VariableFlags Flags() const
    {
        return flags_;
    }

    checker::Type *TsType() const
    {
        return ts_type_;
    }

    Scope *GetScope() const
    {
        return scope_;
    }

    void SetTsType(checker::Type *ts_type)
    {
        ts_type_ = ts_type;
    }

    void SetScope(binder::Scope *scope)
    {
        scope_ = scope;
    }

    void AddFlag(VariableFlags flag)
    {
        flags_ |= flag;
    }

    bool HasFlag(VariableFlags flag) const
    {
        return (flags_ & flag) != 0;
    }

    void RemoveFlag(VariableFlags flag)
    {
        flags_ &= ~flag;
    }

    void Reset(Decl *decl, VariableFlags flags)
    {
        decl_ = decl;
        flags_ = flags;
    }

    bool LexicalBound() const
    {
        return HasFlag(VariableFlags::LEXICAL_BOUND);
    }

    const util::StringView &Name() const;
    virtual void SetLexical(Scope *scope) = 0;

protected:
    explicit Variable(Decl *decl, VariableFlags flags) : decl_(decl), flags_(flags) {}
    explicit Variable(VariableFlags flags) : flags_(flags) {}

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    Decl *decl_ {};
    VariableFlags flags_ {};
    checker::Type *ts_type_ {};
    Scope *scope_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class LocalVariable : public Variable {
public:
    explicit LocalVariable(Decl *decl, VariableFlags flags);
    explicit LocalVariable(VariableFlags flags);

    VariableType Type() const override
    {
        return VariableType::LOCAL;
    }

    void BindVReg(compiler::VReg vreg)
    {
        ASSERT(!LexicalBound());
        vreg_ = vreg;
    }

    void BindLexEnvSlot(uint32_t slot)
    {
        ASSERT(!LexicalBound());
        AddFlag(VariableFlags::LEXICAL_BOUND);
        vreg_.SetIndex(slot);
    }

    compiler::VReg Vreg() const
    {
        return vreg_;
    }

    compiler::VReg &Vreg()
    {
        return vreg_;
    }

    uint32_t LexIdx() const
    {
        ASSERT(LexicalBound());
        return vreg_.GetIndex();
    }

    void SetLexical([[maybe_unused]] Scope *scope) override;
    LocalVariable *Copy(ArenaAllocator *allocator, Decl *decl) const;

private:
    compiler::VReg vreg_ {};
};

class GlobalVariable : public Variable {
public:
    explicit GlobalVariable(Decl *decl, VariableFlags flags) : Variable(decl, flags) {}

    VariableType Type() const override
    {
        return VariableType::GLOBAL;
    }

    void SetLexical([[maybe_unused]] Scope *scope) override;
};

class ModuleVariable : public Variable {
public:
    explicit ModuleVariable(Decl *decl, VariableFlags flags) : Variable(decl, flags) {}

    VariableType Type() const override
    {
        return VariableType::MODULE;
    }

    compiler::VReg &ModuleReg()
    {
        return module_reg_;
    }

    compiler::VReg ModuleReg() const
    {
        return module_reg_;
    }

    const util::StringView &ExoticName() const
    {
        return exotic_name_;
    }

    util::StringView &ExoticName()
    {
        return exotic_name_;
    }

    void SetLexical([[maybe_unused]] Scope *scope) override;

private:
    compiler::VReg module_reg_ {};
    util::StringView exotic_name_ {};
};

class EnumVariable : public Variable {
public:
    explicit EnumVariable(Decl *decl, bool back_reference = false)
        : Variable(decl, VariableFlags::NONE), back_reference_(back_reference)
    {
    }

    VariableType Type() const override
    {
        return VariableType::ENUM;
    }

    void SetValue(EnumMemberResult value)
    {
        value_ = value;
    }

    const EnumMemberResult &Value() const
    {
        return value_;
    }

    bool BackReference() const
    {
        return back_reference_;
    }

    void SetBackReference()
    {
        back_reference_ = true;
    }

    void ResetDecl(Decl *decl);

    void SetLexical([[maybe_unused]] Scope *scope) override;

private:
    EnumMemberResult value_ {};
    bool back_reference_ {};
};
}  // namespace panda::es2panda::binder
#endif
