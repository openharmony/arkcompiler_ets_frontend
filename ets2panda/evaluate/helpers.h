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

#ifndef ES2PANDA_EVALUATE_HELPERS_H
#define ES2PANDA_EVALUATE_HELPERS_H

#include "checker/ETSchecker.h"
#include "evaluate/varbinderScopes.h"
#include "ir/astNodeFlags.h"
#include "varbinder/ETSBinder.h"

#include "libpandafile/field_data_accessor.h"
#include "libpandafile/file.h"
#include "libpandafile/include/type.h"

#include <optional>
#include <string>

namespace ark::es2panda::checker {
class Type;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::ir {
class BlockStatement;
class Identifier;
class TypeNode;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::parser {
class Program;
}  // namespace ark::es2panda::parser

namespace ark::es2panda::evaluate {

class SafeStateScope final {
public:
    explicit SafeStateScope(checker::ETSChecker *checker);

    ~SafeStateScope();

    NO_COPY_SEMANTIC(SafeStateScope);
    NO_MOVE_SEMANTIC(SafeStateScope);

    void *operator new(size_t) = delete;
    void *operator new[](size_t) = delete;

private:
    checker::ETSChecker *checker_ {nullptr};
    varbinder::Scope *checkerScope_ {nullptr};
    varbinder::GlobalScope *binderTopScope_ {nullptr};
    varbinder::VariableScope *binderVarScope_ {nullptr};
    varbinder::Scope *binderScope_ {nullptr};
    parser::Program *binderProgram_ {nullptr};
    varbinder::RecordTable *recordTable_ {nullptr};
};

static inline constexpr std::string_view DEBUGGER_API_CLASS_NAME = "DebuggerAPI";

#define TYPED_ACCESSOR_NAME_SWITCH(TYPE_NAME_BASE) \
    switch (typeId) {                              \
        case panda_file::Type::TypeId::U1:         \
            return #TYPE_NAME_BASE "Boolean";      \
        case panda_file::Type::TypeId::I8:         \
            return #TYPE_NAME_BASE "Byte";         \
        case panda_file::Type::TypeId::U8:         \
            return #TYPE_NAME_BASE "Short";        \
        case panda_file::Type::TypeId::I16:        \
            [[fallthrough]];                       \
        case panda_file::Type::TypeId::U16:        \
            return #TYPE_NAME_BASE "Char";         \
        case panda_file::Type::TypeId::I32:        \
            [[fallthrough]];                       \
        case panda_file::Type::TypeId::U32:        \
            return #TYPE_NAME_BASE "Int";          \
        case panda_file::Type::TypeId::F32:        \
            return #TYPE_NAME_BASE "Float";        \
        case panda_file::Type::TypeId::F64:        \
            return #TYPE_NAME_BASE "Double";       \
        case panda_file::Type::TypeId::I64:        \
            [[fallthrough]];                       \
        case panda_file::Type::TypeId::U64:        \
            return #TYPE_NAME_BASE "Long";         \
        case panda_file::Type::TypeId::REFERENCE:  \
            return #TYPE_NAME_BASE "Object";       \
        default:                                   \
            UNREACHABLE();                         \
            return "";                             \
    }                                              \
    return ""

constexpr inline std::string_view CreateGetterName(panda_file::Type::TypeId typeId)
{
    TYPED_ACCESSOR_NAME_SWITCH(getLocal);
}

constexpr inline std::string_view CreateSetterName(panda_file::Type::TypeId typeId)
{
    TYPED_ACCESSOR_NAME_SWITCH(setLocal);
}

#undef TYPED_ACCESSOR_NAME_SWITCH

template <typename F>
void DoScopedAction(checker::ETSChecker *checker, parser::Program *program, varbinder::Scope *scope,
                    ir::AstNode *parentClass, F &&action)
{
    ASSERT(checker);
    // Must enter either program global scope or a local scope.
    ASSERT(program != nullptr || scope != nullptr);

    SafeStateScope s(checker);

    auto *binder = checker->VarBinder()->AsETSBinder();

    auto runInScope = [checker, binder, scope, parentClass](auto &&f) {
        RecordTableClassScope recordTableScope(binder, parentClass);
        if (scope != nullptr) {
            auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(binder, scope);
            checker::ScopeContext checkerScope(checker, scope);
            f();
        } else {
            f();
        }
    };

    if (program != nullptr && program != binder->Program()) {
        // Save checker scope because it can differ from binder's scope.
        checker::ScopeContext savedCheckerScope(checker, checker->Scope());
        {
            ProgramScope rcScope(binder, program);
            checker->Initialize(binder);

            runInScope(std::move(action));
        }
        // Switch checker's state back after leaving another program's context.
        checker->Initialize(binder);
    } else {
        runInScope(std::move(action));
    }
}

ir::TypeNode *ToTypeNode(std::string_view typeSignature, checker::ETSChecker *checker);

ir::TypeNode *PandaTypeToTypeNode(const panda_file::File &pf, panda_file::FieldDataAccessor &fda,
                                  checker::ETSChecker *checker);

ir::TypeNode *PandaTypeToTypeNode(const panda_file::File &pf, panda_file::Type pandaType,
                                  panda_file::File::EntityId classId, checker::ETSChecker *checker);

std::optional<std::string> ToTypeName(std::string_view typeSignature, checker::GlobalTypesHolder *globalTypes);

panda_file::Type::TypeId GetTypeId(std::string_view typeSignature);

ir::BlockStatement *GetEnclosingBlock(ir::Identifier *ident);

ir::ModifierFlags GetModifierFlags(panda_file::FieldDataAccessor &fda);

// Adds `extProgram` into external programs list of the given `program`.
void AddExternalProgram(parser::Program *program, parser::Program *extProgram, std::string_view moduleName);

}  // namespace ark::es2panda::evaluate

#endif /* HELPERS_H */
