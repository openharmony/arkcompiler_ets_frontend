/*
 * Copyright (c) 2023 - 2025 Huawei Device Co., Ltd.
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

#ifndef PANDA_GLOBALCLASSHANDLER_H
#define PANDA_GLOBALCLASSHANDLER_H

#include "compiler/lowering/ets/topLevelStmts/globalDeclTransformer.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "parser/program/program.h"
#include "public/public.h"
#include "ir/astNode.h"

namespace ark::es2panda::compiler {

class GlobalClassHandler {
public:
    using ModuleDependencies = ArenaUnorderedSet<parser::Program *>;

    struct GlobalStmts {
        parser::Program *program;
        ArenaVector<ir::Statement *> statements;
    };
    explicit GlobalClassHandler(parser::ETSParser *parser, ArenaAllocator *allocator)
        : parser_(parser), allocator_(allocator), packageInitializerBlockCount_(allocator->Adapter()) {};

    /**
     * Each "Module" has it's own global class, which contains all top level statements across "module"
     * Result - creation of global class and _$init$_ method
     * @param programs - vector of files in module
     */
    void SetupGlobalClass(const ArenaVector<parser::Program *> &programs, const ModuleDependencies *moduleDependencies);
    void static MergeNamespace(ArenaVector<ir::ETSModule *> &namespaces, parser::Program *program);
    void CheckPackageMultiInitializerBlock(util::StringView packageName,
                                           const ArenaVector<ArenaVector<ir::Statement *>> &initializerBlocks);

private:
    /**
     * Move top level statements to _$init$_ and
     * @param program program of module
     * @param init_statements statements which should be executed
     */
    void SetupGlobalMethods(parser::Program *program, ArenaVector<ir::Statement *> &&statements);
    void AddStaticBlockToClass(ir::AstNode *node);
    void CollectProgramGlobalClasses(parser::Program *program, ArenaVector<ir::ETSModule *> namespaces);
    ir::ClassDeclaration *TransformNamespace(ir::ETSModule *ns, parser::Program *program);
    ir::ClassDeclaration *CreateTransformedClass(ir::ETSModule *ns);
    template <class Node>
    void CollectExportedClasses(parser::Program *program, ir::ClassDefinition *classDef,
                                const ArenaVector<Node *> &statements);
    void CollectReExportedClasses(parser::Program *program, ir::ClassDefinition *classDef,
                                  const ir::ETSReExportDeclaration *reExport);
    void CollectNamespaceExportedClasses(parser::Program *program, ir::ClassDefinition *classDef);
    void SetupGlobalMethods(parser::Program *program, ArenaVector<ir::Statement *> &&initStatements,
                            ir::ClassDefinition *globalClass, bool isDeclare);
    void SetupInitializerBlock(parser::Program *program, ArenaVector<ArenaVector<ir::Statement *>> &&initializerBlock,
                               ir::ClassDefinition *globalClass);
    ArenaVector<ir::ClassDeclaration *> TransformNamespaces(ArenaVector<ir::ETSModule *> &namespaces,
                                                            parser::Program *program);

    ir::ClassDeclaration *CreateGlobalClass(const parser::Program *globalProgram);
    ir::ClassStaticBlock *CreateStaticBlock(ir::ClassDefinition *classDef);
    ir::MethodDefinition *CreateGlobalMethod(std::string_view name, ArenaVector<ir::Statement *> &&statements,
                                             const parser::Program *program);
    void AddInitCallToStaticBlock(ir::ClassDefinition *globalClass, ir::MethodDefinition *initMethod);
    void AddInitializerBlockToStaticBlock(ir::ClassDefinition *globalClass,
                                          ArenaVector<ir::Statement *> &&initializerBlocks);

    ArenaVector<ArenaVector<ir::Statement *>> FormInitStaticBlockMethodStatements(
        parser::Program *program, const ModuleDependencies *moduleDependencies,
        ArenaVector<GlobalStmts> &&initStatements);
    void TransformBrokenNamespace(ir::AstNode *node, parser::Program *program);

    ArenaVector<ir::Statement *> FormInitMethodStatements(parser::Program *program,
                                                          const ModuleDependencies *moduleDependencies,
                                                          ArenaVector<GlobalStmts> &&initStatements);

    void FormDependentInitTriggers(ArenaVector<ir::Statement *> &statements,
                                   const ModuleDependencies *moduleDependencies);

    GlobalDeclTransformer::ResultT CollectProgramGlobalStatements(ArenaVector<ir::Statement *> &stmts,
                                                                  ir::ClassDefinition *classDef,
                                                                  ir::Statement const *stmt);

    ir::Identifier *RefIdent(const util::StringView &name);

    parser::ETSParser *const parser_;
    ArenaAllocator *const allocator_;
    ArenaUnorderedSet<util::StringView> packageInitializerBlockCount_;
};
}  // namespace ark::es2panda::compiler

#endif  // PANDA_GLOBALCLASSHANDLER_H
