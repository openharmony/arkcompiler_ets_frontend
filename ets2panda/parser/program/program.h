/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "util/es2pandaMacros.h"
#include "mem/pool_manager.h"
#include "os/filesystem.h"
#include "util/ustring.h"
#include "util/path.h"
#include "util/importPathManager.h"
#include "varbinder/varbinder.h"
#include <lexer/token/sourceLocation.h>

#include <set>

namespace ark::es2panda::ir {
class BlockStatement;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::varbinder {
class VarBinder;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::compiler {
class CFG;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::parser {
enum class ScriptKind { SCRIPT, MODULE, STDLIB };
enum EntityType { CLASS_PROPERTY = 0, METHOD_DEFINITION = 1, CLASS_DEFINITION = 2, TS_INTERFACE_DECLARATION = 3 };

class Program {
public:
    using ExternalSource = ArenaUnorderedMap<util::StringView, ArenaVector<Program *>>;
    using DirectExternalSource = ArenaUnorderedMap<util::StringView, ArenaVector<Program *>>;

    using ETSNolintsCollectionMap = ArenaUnorderedMap<const ir::AstNode *, ArenaSet<ETSWarnings>>;

    template <typename T>
    static Program NewProgram(ArenaAllocator *allocator)
    {
        auto *varbinder = allocator->New<T>(allocator);
        return Program(allocator, varbinder);
    }

    Program(ArenaAllocator *allocator, varbinder::VarBinder *varbinder);

    ~Program();

    void SetKind(ScriptKind kind)
    {
        kind_ = kind;
    }

    NO_COPY_SEMANTIC(Program);
    DEFAULT_MOVE_SEMANTIC(Program);

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
        return sourceCode_;
    }

    const util::StringView &SourceFilePath() const
    {
        return sourceFile_.GetPath();
    }

    const util::Path &SourceFile() const
    {
        return sourceFile_;
    }

    util::StringView SourceFileFolder() const
    {
        return sourceFileFolder_;
    }

    util::StringView FileName() const
    {
        return sourceFile_.GetFileName();
    }

    util::StringView FileNameWithExtension() const
    {
        return sourceFile_.GetFileNameWithExtension();
    }

    util::StringView AbsoluteName() const
    {
        return sourceFile_.GetAbsolutePath();
    }

    util::StringView ResolvedFilePath() const
    {
        return resolvedFilePath_;
    }

    util::StringView RelativeFilePath() const
    {
        // for js source files, just return file name.
        return relativeFilePath_.Empty() ? FileNameWithExtension() : relativeFilePath_;
    }

    void SetRelativeFilePath(const util::StringView &relPath)
    {
        relativeFilePath_ = relPath;
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
        MaybeTransformToDeclarationModule();
    }

    ir::ClassDefinition *GlobalClass()
    {
        return globalClass_;
    }

    const ir::ClassDefinition *GlobalClass() const
    {
        return globalClass_;
    }

    void SetGlobalClass(ir::ClassDefinition *globalClass)
    {
        globalClass_ = globalClass;
    }

    ExternalSource &ExternalSources()
    {
        return externalSources_;
    }

    const ExternalSource &ExternalSources() const
    {
        return externalSources_;
    }

    DirectExternalSource &DirectExternalSources()
    {
        return directExternalSources_;
    }

    const DirectExternalSource &DirectExternalSources() const
    {
        return directExternalSources_;
    }

    const lexer::SourcePosition &PackageStart() const
    {
        return packageStartPosition_;
    }

    void SetPackageStart(const lexer::SourcePosition &start)
    {
        packageStartPosition_ = start;
    }

    void SetSource(const util::StringView &sourceCode, const util::StringView &sourceFilePath,
                   const util::StringView &sourceFileFolder)
    {
        sourceCode_ = sourceCode;
        sourceFile_ = util::Path(sourceFilePath, Allocator());
        sourceFileFolder_ = sourceFileFolder;
    }

    void SetSource(const ark::es2panda::SourceFile &sourceFile)
    {
        sourceCode_ = util::UString(sourceFile.source, Allocator()).View();
        sourceFile_ = util::Path(sourceFile.filePath, Allocator());
        sourceFileFolder_ = util::UString(sourceFile.fileFolder, Allocator()).View();
        resolvedFilePath_ = util::UString(sourceFile.resolvedPath, Allocator()).View();
        moduleInfo_.isDeclForDynamicStaticInterop = sourceFile.isDeclForDynamicStaticInterop;
    }

    void SetPackageInfo(const util::StringView &name, util::ModuleKind kind);

    const auto &ModuleInfo() const
    {
        return moduleInfo_;
    }

    util::StringView ModuleName() const
    {
        return moduleInfo_.moduleName;
    }

    util::StringView ModulePrefix() const
    {
        return moduleInfo_.modulePrefix;
    }

    bool IsSeparateModule() const
    {
        return moduleInfo_.kind == util::ModuleKind::MODULE;
    }

    bool IsDeclarationModule() const
    {
        return moduleInfo_.kind == util::ModuleKind::DECLARATION;
    }

    bool IsPackage() const
    {
        return moduleInfo_.kind == util::ModuleKind::PACKAGE;
    }

    void MarkASTAsChecked()
    {
        isASTchecked_ = true;
    }

    bool IsASTChecked() const
    {
        return isASTchecked_;
    }

    bool IsStdLib() const
    {
        // NOTE (hurton): temporary solution, needs rework when std sources are renamed
        return (ModuleName().Mutf8().rfind("std.", 0) == 0) || (ModuleName().Mutf8().rfind("escompat", 0) == 0) ||
               (FileName().Is("etsstdlib"));
    }

    varbinder::ClassScope *GlobalClassScope();
    const varbinder::ClassScope *GlobalClassScope() const;

    varbinder::GlobalScope *GlobalScope();
    const varbinder::GlobalScope *GlobalScope() const;

    std::string Dump() const;

    void DumpSilent() const;

    void AddNodeToETSNolintCollection(const ir::AstNode *node, const std::set<ETSWarnings> &warningsCollection);
    bool NodeContainsETSNolint(const ir::AstNode *node, ETSWarnings warning);

    std::vector<std::pair<std::string, ir::AstNode *>> &DeclGenExportNodes()
    {
        // NOTE: ExportNodes is not supported now.
        return declGenExportNodes_;
    }

    void AddDeclGenExportNode(const std::string &declGenExportStr, ir::AstNode *node)
    {
        declGenExportNodes_.emplace_back(declGenExportStr, node);
    }

    // The name "IsDied", because correct value of canary is a necessary condition for the life of "Program", but
    // not sufficient
    bool IsDied() const
    {
        // You can't add one method to ignore list of es2panda_lib generation,
        // so in release mode method is exist, return "false" and is not used anywhere.
#ifndef NDEBUG
        return poisonValue_ != POISON_VALUE;
#else
        return false;
#endif
    }

    compiler::CFG *GetCFG();
    const compiler::CFG *GetCFG() const;

private:
    void MaybeTransformToDeclarationModule();

    ArenaAllocator *allocator_ {};
    varbinder::VarBinder *varbinder_ {};
    ir::BlockStatement *ast_ {};
    ir::ClassDefinition *globalClass_ {};
    util::StringView sourceCode_ {};
    util::Path sourceFile_ {};
    util::StringView sourceFileFolder_ {};
    util::StringView resolvedFilePath_ {};
    util::StringView relativeFilePath_ {};
    ExternalSource externalSources_;
    DirectExternalSource directExternalSources_;
    ScriptKind kind_ {};
    ScriptExtension extension_ {};
    ETSNolintsCollectionMap etsnolintCollection_;
    util::ModuleInfo moduleInfo_;
    bool isASTchecked_ {};
    lexer::SourcePosition packageStartPosition_ {};
    compiler::CFG *cfg_;
    std::vector<std::pair<std::string, ir::AstNode *>> declGenExportNodes_;

#ifndef NDEBUG
    const static uint32_t POISON_VALUE {0x12346789};
    uint32_t poisonValue_ {POISON_VALUE};
#endif
};
}  // namespace ark::es2panda::parser

#endif
