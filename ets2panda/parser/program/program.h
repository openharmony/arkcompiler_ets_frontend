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

#ifndef ES2PANDA_PARSER_INCLUDE_PROGRAM_H
#define ES2PANDA_PARSER_INCLUDE_PROGRAM_H

#include "macros.h"
#include "mem/pool_manager.h"
#include "os/filesystem.h"
#include "util/ustring.h"
#include "util/path.h"
#include "varbinder/varbinder.h"

#include "es2panda.h"

namespace panda::es2panda::ir {
class BlockStatement;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::varbinder {
class VarBinder;
}  // namespace panda::es2panda::varbinder

namespace panda::es2panda::parser {
enum class ScriptKind { SCRIPT, MODULE, STDLIB };

class Program {
public:
    using ExternalSource = ArenaUnorderedMap<util::StringView, ArenaVector<Program *>>;
    template <typename T>
    static Program NewProgram(ArenaAllocator *allocator)
    {
        auto *varbinder = allocator->New<T>(allocator);
        return Program(allocator, varbinder);
    }

    Program(ArenaAllocator *allocator, varbinder::VarBinder *varbinder)
        : allocator_(allocator),
          varbinder_(varbinder),
          external_sources_(allocator_->Adapter()),
          extension_(varbinder->Extension())
    {
    }

    void SetKind(ScriptKind kind)
    {
        kind_ = kind;
    }

    NO_COPY_SEMANTIC(Program);
    DEFAULT_MOVE_SEMANTIC(Program);

    ~Program() = default;

    ArenaAllocator *Allocator() const
    {
        return allocator_;
    }

    const varbinder::VarBinder *VarBinder() const
    {
        return varbinder_;
    }

    varbinder::VarBinder *VarBinder()
    {
        return varbinder_;
    }

    ScriptExtension Extension() const
    {
        return extension_;
    }

    ScriptKind Kind() const
    {
        return kind_;
    }

    util::StringView SourceCode() const
    {
        return source_code_;
    }

    util::StringView SourceFilePath() const
    {
        return source_file_path_.GetPath();
    }

    util::StringView SourceFileFolder() const
    {
        return source_file_folder_;
    }

    util::StringView FileName() const
    {
        return file_name_;
    }

    util::StringView AbsoluteName() const
    {
        return absolute_name_;
    }

    util::StringView ResolvedFilePath() const
    {
        return resolved_file_path_;
    }

    ir::BlockStatement *Ast()
    {
        return ast_;
    }

    const ir::BlockStatement *Ast() const
    {
        return ast_;
    }

    void SetAst(ir::BlockStatement *ast)
    {
        ast_ = ast;
    }

    ir::ClassDefinition *GlobalClass()
    {
        return global_class_;
    }

    const ir::ClassDefinition *GlobalClass() const
    {
        return global_class_;
    }

    void SetGlobalClass(ir::ClassDefinition *global_class)
    {
        global_class_ = global_class;
    }

    ExternalSource &ExternalSources()
    {
        return external_sources_;
    }

    const ExternalSource &ExternalSources() const
    {
        return external_sources_;
    }

    void SetSource(const util::StringView &source_code, const util::StringView &source_file_path,
                   const util::StringView &source_file_folder)
    {
        source_code_ = source_code;
        source_file_path_ = util::Path(source_file_path, Allocator());
        source_file_folder_ = source_file_folder;
        absolute_name_ = util::UString(os::GetAbsolutePath(source_file_path.Utf8()), Allocator()).View();
    }

    void SetSource(const panda::es2panda::SourceFile &source_file)
    {
        source_code_ = util::UString(source_file.source, Allocator()).View();
        source_file_path_ = util::Path(source_file.file_path, Allocator());
        source_file_folder_ = util::UString(source_file.file_folder, Allocator()).View();
        absolute_name_ = source_file_path_.GetAbsolutePath();
        resolved_file_path_ = util::UString(source_file.resolved_path, Allocator()).View();
    }

    const util::StringView &GetPackageName() const
    {
        return package_name_;
    }

    void SetPackageName(util::StringView package_name)
    {
        package_name_ = package_name;
    }

    void SetFileName(util::StringView file_name)
    {
        file_name_ = util::UString(file_name, Allocator()).View();
    }

    void SetAbsoluteName(util::StringView absoule_name)
    {
        absolute_name_ = util::UString(absoule_name, Allocator()).View();
    }

    const bool &IsEntryPoint() const
    {
        return entry_point_;
    }

    void MarkEntry()
    {
        entry_point_ = true;
    }

    varbinder::ClassScope *GlobalClassScope();
    const varbinder::ClassScope *GlobalClassScope() const;

    varbinder::GlobalScope *GlobalScope();
    const varbinder::GlobalScope *GlobalScope() const;

    util::StringView PackageClassName(util::StringView class_name);

    std::string Dump() const;

    void DumpSilent() const;

private:
    ArenaAllocator *allocator_ {};
    varbinder::VarBinder *varbinder_ {};
    ir::BlockStatement *ast_ {};
    ir::ClassDefinition *global_class_ {};
    util::StringView source_code_ {};
    util::Path source_file_path_ {};
    util::StringView source_file_folder_ {};
    util::StringView package_name_ {};
    util::StringView file_name_ {};
    util::StringView absolute_name_ {};
    util::StringView resolved_file_path_ {};
    ExternalSource external_sources_;
    ScriptKind kind_ {};
    ScriptExtension extension_ {};
    bool entry_point_ {};
};
}  // namespace panda::es2panda::parser

#endif
