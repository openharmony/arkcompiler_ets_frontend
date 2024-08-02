/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

#include "parser/program/program.h"
#include "public/public.h"
#include "ir/astNode.h"

namespace ark::es2panda::compiler {

class GlobalClassHandler {
public:
    using TriggeringCCtorMethodProgramPair = std::pair<util::StringView, parser::Program *>;
    using TriggeringCCtorMethodsAndPrograms =
        ArenaUnorderedMap<util::StringView, ArenaVector<TriggeringCCtorMethodProgramPair>>;

    struct GlobalStmts {
        parser::Program *program;
        ArenaVector<ir::Statement *> statements;
    };
    explicit GlobalClassHandler(ArenaAllocator *allocator) : allocator_(allocator) {};

    /**
     * Each "Module" has it's own global class, which contains all top level statements across "module"
     * Result - creation of global class and _$init$_ method
     * @param programs - vector of files in module
     */
    void InitGlobalClass(const ArenaVector<parser::Program *> &programs,
                         const TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethods);
    util::UString ReplaceSpecialCharacters(util::UString *word) const;
    util::StringView FormTriggeringCCtorMethodName(util::StringView importPath) const;

    constexpr static std::string_view TRIGGER_CCTOR = "_$trigger_cctor$_";

private:
    /**
     * Move top level statements to _$init$_ and
     * @param program program of module
     * @param init_statements statements which should be executed
     */

    void AddTriggerCctrMethodsToInit(ir::BlockStatement *blockBody,
                                     const TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms);
    void InitCallToCCTOR(parser::Program *program,
                         const TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms,
                         const ArenaVector<GlobalStmts> &initStatements, bool mainExists = false,
                         bool topLevelStatementsExist = false, bool triggeringCCtorMethodExists = false);

private:
    ir::MethodDefinition *CreateAndFillTopLevelMethod(
        parser::Program *program,
        const GlobalClassHandler::TriggeringCCtorMethodsAndPrograms *triggeringCCtorMethodsAndPrograms,
        const ArenaVector<GlobalClassHandler::GlobalStmts> &initStatements, const std::string_view name,
        bool exportFunction = false);
    void InitGlobalClass(ir::ClassDefinition *classDef, parser::ScriptKind scriptKind);
    ir::ClassDeclaration *CreateGlobalClass();
    ir::ClassStaticBlock *CreateCCtor(const ArenaVector<ir::AstNode *> &properties, const lexer::SourcePosition &loc,
                                      bool allowEmptyCctor);

    /**
     *
     * @param global_stmts leave only declarations here
     * @param class_def add new properties such as methods and fields
     * @param addInitializer $init$ should contain global variable initializers
     * @return Statements, which should be executed before the start
     */
    ArenaVector<ir::Statement *> MakeGlobalStatements(ir::BlockStatement *globalStmts, ir::ClassDefinition *classDef,
                                                      bool addInitializer);

    void AddInitCall(ir::ClassDefinition *globalClass, ir::MethodDefinition *initMethod);

    ir::Identifier *RefIdent(const util::StringView &name);

private:
    constexpr static std::string_view INIT_NAME = compiler::Signatures::INIT_METHOD;
    ArenaAllocator *const allocator_;
};
}  // namespace ark::es2panda::compiler

#endif  // PANDA_GLOBALCLASSHANDLER_H
