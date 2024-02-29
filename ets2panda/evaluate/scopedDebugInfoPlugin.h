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

#ifndef ES2PANDA_EVALUATE_SCOPED_DEBUG_INFO_PLUGIN_H
#define ES2PANDA_EVALUATE_SCOPED_DEBUG_INFO_PLUGIN_H

#include "evaluate/classDeclarationCreator.h"
#include "evaluate/debugInfoStorage.h"
#include "evaluate/evaluateContext.h"
#include "evaluate/helpers.h"
#include "evaluate/nonRecursiveIrChecker.h"
#include "evaluate/proxyProgramsMap.h"

#include "libpandafile/debug_info_extractor.h"
#include "libpandafile/field_data_accessor.h"
#include "libpandafile/file.h"

namespace ark::es2panda::ir {
class AstNode;
class BlockStatement;
class ETSImportDeclaration;
class Statement;
}  // namespace ark::es2panda::ir

namespace ark::es2panda::varbinder {
class Variable;
}  // namespace ark::es2panda::varbinder

namespace ark::es2panda::evaluate {

// Context-dependent debug info plugin. Must be created before parsing phase.
class ScopedDebugInfoPlugin final {
public:
    using RegisterNumber = int32_t;

public:
    explicit ScopedDebugInfoPlugin(parser::Program *globalProgram, checker::ETSChecker *checker,
                                   const CompilerOptions &options);

    NO_COPY_SEMANTIC(ScopedDebugInfoPlugin);
    NO_MOVE_SEMANTIC(ScopedDebugInfoPlugin);

    ~ScopedDebugInfoPlugin() = default;

    /**
     * @brief Searches debug-info for the given identifier
     * @param ident node with name of either a local or global variable or a class
     */
    varbinder::Variable *FindIdentifier(ir::Identifier *ident);

    /**
     * @brief Searches debug-info for the given class
     * On success creates IR for this and all dependencies.
     */
    varbinder::Variable *FindClass(ir::Identifier *ident);

    /**
     * @brief Adds collected prologue and epilogue statements in the block
     * In effect, previously collected prologue-epilogue statements are dropped.
     */
    void AddPrologueEpilogue(ir::BlockStatement *block);

    /**
     * @brief Initialization before ETSChecker starts checking AST
     * Since we can resolve references like `new A()`, that resolved before ETSChecker was started,
     * we need such a precheck call.
     */
    void PreCheck();

    /**
     * @brief Finalization after ETSChecker checks the main program
     */
    void PostCheck();

private:
    using PrologueEpiloguePair = std::pair<ArenaVector<ir::Statement *>, ArenaVector<ir::Statement *>>;
    using PrologueEpilogueMap = ArenaUnorderedMap<ir::BlockStatement *, PrologueEpiloguePair>;
    using GlobalEntityHelper = varbinder::Variable *(ScopedDebugInfoPlugin::*)(util::StringView, util::StringView,
                                                                               util::StringView, parser::Program *);

private:
    template <bool IsPrologue>
    void RegisterPrologueEpilogue(ir::BlockStatement *block, ir::Statement *stmt)
    {
        ASSERT(block);
        ASSERT(stmt);

        auto iter = prologueEpilogueMap_.find(block);
        if (iter == prologueEpilogueMap_.end()) {
            ArenaVector<ir::Statement *> vec(1, stmt, Allocator()->Adapter());
            if constexpr (IsPrologue) {
                prologueEpilogueMap_.emplace(block,
                                             std::make_pair(vec, ArenaVector<ir::Statement *>(Allocator()->Adapter())));
            } else {
                prologueEpilogueMap_.emplace(block,
                                             std::make_pair(ArenaVector<ir::Statement *>(Allocator()->Adapter()), vec));
            }
        } else {
            if constexpr (IsPrologue) {
                iter->second.first.push_back(stmt);
            } else {
                iter->second.second.push_back(stmt);
            }
        }
    }

    // Imports a global entity - variable, function (whole overload set) or class.
    // Creates the entity if it was not created before.
    template <typename F>
    varbinder::Variable *ImportGlobalEntity(util::StringView pathToDeclSource, util::StringView declName,
                                            parser::Program *importerProgram, util::StringView importedName,
                                            F &&irCreator)
    {
        parser::Program *program = GetProgram(pathToDeclSource);

        SafeStateScope s(checker_);

        varbinder::Variable *var = nullptr;
        auto &entitiesMap = GetOrCreateEntitiesMap(program);
        auto iter = entitiesMap.find(declName);
        if (iter != entitiesMap.end()) {
            var = iter->second;
        } else {
            var = std::invoke(std::move(irCreator), this, program, pathToDeclSource, declName);
            if (var != nullptr) {
                [[maybe_unused]] auto p = entitiesMap.emplace(declName, var);
                // Must be unique.
                ASSERT(p.second);
            }
        }

        if (var != nullptr && program != importerProgram) {
            auto *importStatement = CreateIrImport(pathToDeclSource, declName, importedName);
            InsertImportStatement(importStatement, importerProgram);
        }

        return var;
    }

    // Initialization methods.
    void ValidateEvaluationOptions(const CompilerOptions &options);

    void CreateContextPrograms(parser::Program *globalProgram);

    // Creates a program with the given package name and adds it as external for the given program.
    // This method must be called once and before running any compiler phases.
    parser::Program *CreateEmptyProgram(parser::Program *globalProgram, std::string_view sourceFilePath,
                                        std::string_view moduleName);

    // Returns non-null Program for the given source file path.
    parser::Program *GetProgram(util::StringView fileName);

    // Search methods.
    varbinder::Variable *FindGlobalVariable(ir::Identifier *ident);
    varbinder::Variable *FindGlobalFunction(ir::Identifier *ident);
    varbinder::Variable *FindLocalVariable(ir::Identifier *ident);

    // IR creation methods.
    varbinder::Variable *CreateIrGlobalMethods(ArenaVector<ir::AstNode *> &createdMethods, parser::Program *program,
                                               util::StringView pathToSource, util::StringView methodDeclName);
    varbinder::Variable *CreateIrGlobalVariable(parser::Program *program, util::StringView pathToSource,
                                                util::StringView varDeclName);
    varbinder::Variable *CreateIrClass(panda_file::File::EntityId classId, parser::Program *classProgram,
                                       util::StringView pathToSource, util::StringView classDeclName);
    ir::ETSImportDeclaration *CreateIrImport(util::StringView pathToDeclSourceFile, util::StringView classDeclName,
                                             util::StringView classImportedName);

    // Utility methods.
    ArenaAllocator *Allocator();

    ArenaUnorderedMap<util::StringView, varbinder::Variable *> &GetOrCreateEntitiesMap(parser::Program *program);

    void InsertImportStatement(ir::Statement *importStatement, parser::Program *importerProgram);

    varbinder::Variable *CreateVarDecl(ir::Identifier *ident, RegisterNumber regNumber,
                                       const std::string &typeSignature);

    // Check wrappers.
    void CheckGlobalEntity(parser::Program *program, ir::AstNode *node, bool mustCheck = true);
    void CheckLocalEntity(ir::AstNode *node);

private:
    checker::ETSChecker *checker_;

    EvaluateContext context_;

    DebugInfoStorage debugInfoStorage_;

    ProxyProgramsMap proxyProgramsMap_;
    NonRecursiveIrChecker irChecker_;
    ClassDeclarationCreator classDeclCreator_;

    PrologueEpilogueMap prologueEpilogueMap_;

    ArenaUnorderedMap<parser::Program *, ArenaUnorderedMap<util::StringView, varbinder::Variable *>> createdEntities_;
};

}  // namespace ark::es2panda::evaluate

#endif /* SCOPED_DEBUG_INFO_PLUGIN_H */
