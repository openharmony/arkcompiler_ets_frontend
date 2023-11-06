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

#ifndef ES2PANDA_recordTable_RECORD_TABLE_H
#define ES2PANDA_recordTable_RECORD_TABLE_H

#include "macros.h"
#include "utils/arena_containers.h"
#include "util/ustring.h"
#include "util/enumbitops.h"

namespace panda::es2panda::parser {
class Program;
}  // namespace panda::es2panda::parser

namespace panda::es2panda::checker {
class Signature;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::ir {
class ClassDefinition;
class TSInterfaceDeclaration;
class Identifier;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::binder {
class FunctionScope;
class BoundContext;

enum class RecordTableFlags : uint32_t {
    NONE = 0U,
    EXTERNAL = 1U << 0U,
};

DEFINE_BITOPS(RecordTableFlags)

class RecordTable {
public:
    explicit RecordTable(ArenaAllocator *allocator, parser::Program *program, RecordTableFlags flags)
        : class_definitions_(allocator->Adapter()),
          interface_declarations_(allocator->Adapter()),
          signatures_(allocator->Adapter()),
          program_(program),
          flags_(flags)
    {
    }

    NO_COPY_SEMANTIC(RecordTable);
    NO_MOVE_SEMANTIC(RecordTable);

    ~RecordTable() = default;

    bool IsExternal() const
    {
        return (flags_ & RecordTableFlags::EXTERNAL) != 0;
    }

    ArenaSet<ir::ClassDefinition *> &ClassDefinitions()
    {
        return class_definitions_;
    }

    const ArenaSet<ir::ClassDefinition *> &ClassDefinitions() const
    {
        return class_definitions_;
    }

    ArenaSet<ir::TSInterfaceDeclaration *> &InterfaceDeclarations()
    {
        return interface_declarations_;
    }

    const ArenaSet<ir::TSInterfaceDeclaration *> &InterfaceDeclarations() const
    {
        return interface_declarations_;
    }

    ArenaVector<FunctionScope *> &Signatures()
    {
        return signatures_;
    }

    const ArenaVector<FunctionScope *> &Signatures() const
    {
        return signatures_;
    }

    void SetClassDefinition(ir::ClassDefinition *class_definition)
    {
        record_ = class_definition;
    }

    ir::ClassDefinition *ClassDefinition()
    {
        return std::holds_alternative<ir::ClassDefinition *>(record_) ? std::get<ir::ClassDefinition *>(record_)
                                                                      : nullptr;
    }

    const ir::ClassDefinition *ClassDefinition() const
    {
        return std::holds_alternative<ir::ClassDefinition *>(record_) ? std::get<ir::ClassDefinition *>(record_)
                                                                      : nullptr;
    }

    void SetInterfaceDeclaration(ir::TSInterfaceDeclaration *interface_declaration)
    {
        record_ = interface_declaration;
    }

    ir::TSInterfaceDeclaration *InterfaceDeclaration()
    {
        return std::holds_alternative<ir::TSInterfaceDeclaration *>(record_)
                   ? std::get<ir::TSInterfaceDeclaration *>(record_)
                   : nullptr;
    }

    const ir::TSInterfaceDeclaration *InterfaceDeclaration() const
    {
        return std::holds_alternative<ir::TSInterfaceDeclaration *>(record_)
                   ? std::get<ir::TSInterfaceDeclaration *>(record_)
                   : nullptr;
    }

    void SetProgram(parser::Program *program)
    {
        program_ = program;
    }

    parser::Program *Program()
    {
        return program_;
    }

    const parser::Program *Program() const
    {
        return program_;
    }

    util::StringView RecordName() const;

private:
    friend class BoundContext;
    using RecordHolder = std::variant<ir::ClassDefinition *, ir::TSInterfaceDeclaration *, std::nullptr_t>;

    ArenaSet<ir::ClassDefinition *> class_definitions_;
    ArenaSet<ir::TSInterfaceDeclaration *> interface_declarations_;
    ArenaVector<binder::FunctionScope *> signatures_;
    RecordHolder record_ {nullptr};
    parser::Program *program_ {};
    BoundContext *bound_ctx_ {};
    RecordTableFlags flags_ {};
};

class BoundContext {
public:
    explicit BoundContext(RecordTable *record_table, ir::ClassDefinition *class_def);
    explicit BoundContext(RecordTable *record_table, ir::TSInterfaceDeclaration *interface_decl);
    ~BoundContext();

    NO_COPY_SEMANTIC(BoundContext);
    NO_MOVE_SEMANTIC(BoundContext);

    void *operator new(size_t) = delete;
    void *operator new[](size_t) = delete;

    util::StringView FormRecordName() const;

private:
    BoundContext *prev_;
    RecordTable *record_table_;
    RecordTable::RecordHolder saved_record_ {nullptr};
    ir::Identifier *record_ident_;
};

}  // namespace panda::es2panda::binder

#endif
