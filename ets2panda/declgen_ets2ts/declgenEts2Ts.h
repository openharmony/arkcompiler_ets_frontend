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

#ifndef ES2PANDA_DECLGEN_ETS2TS_H
#define ES2PANDA_DECLGEN_ETS2TS_H

#include "parser/program/program.h"
#include "checker/ETSchecker.h"
#include "libpandabase/os/file.h"
#include "libpandabase/utils/arena_containers.h"
#include "util/options.h"
#include "util/diagnosticEngine.h"

namespace ark::es2panda::declgen_ets2ts {

struct DeclgenOptions {
    bool exportAll = false;
    std::string outputDeclEts;
    std::string outputEts;
};

// Consume program after checker stage and generate out_path typescript file with declarations
bool GenerateTsDeclarations(checker::ETSChecker *checker, const ark::es2panda::parser::Program *program,
                            const DeclgenOptions &declgenOptions);

class TSDeclGen {
public:
    TSDeclGen(checker::ETSChecker *checker, const ark::es2panda::parser::Program *program)
        : checker_(checker),
          program_(program),
          diagnosticEngine_(checker->DiagnosticEngine()),
          allocator_(SpaceType::SPACE_TYPE_COMPILER, nullptr, true),
          indirectDependencyObjects_(allocator_.Adapter()),
          typeAliasMap_(allocator_.Adapter())
    {
    }

    void SetDeclgenOptions(const DeclgenOptions &options)
    {
        declgenOptions_ = options;
    }

    const DeclgenOptions &GetDeclgenOptions()
    {
        return declgenOptions_;
    }

    void Generate();

    std::string GetDtsOutput() const
    {
        return outputDts_.str();
    }

    std::string GetTsOutput() const
    {
        return outputTs_.str();
    }

    static constexpr std::string_view INDENT = "    ";

private:
    void LogError(const diagnostic::DiagnosticKind &kind, const util::DiagnosticMessageParams &params,
                  const lexer::SourcePosition &pos);
    void LogWarning(const diagnostic::DiagnosticKind &kind, const util::DiagnosticMessageParams &params,
                    const lexer::SourcePosition &pos);

    const ir::Identifier *GetKeyIdent(const ir::Expression *key);

    void GenType(const checker::Type *checkerType);
    void GenFunctionType(const checker::ETSFunctionType *functionType, const ir::MethodDefinition *methodDef = nullptr);
    void GenObjectType(const checker::ETSObjectType *objectType);
    void GenEnumType(const checker::ETSIntEnumType *enumType);
    void GenUnionType(const checker::ETSUnionType *unionType);
    void GenTupleType(const checker::ETSTupleType *tupleType);

    void GenImportDeclaration(const ir::ETSImportDeclaration *importDeclaration);
    void GenReExportDeclaration(const ir::ETSReExportDeclaration *reExportDeclaration);
    void GenTypeAliasDeclaration(const ir::TSTypeAliasDeclaration *typeAlias);
    void GenEnumDeclaration(const ir::TSEnumDeclaration *enumDecl);
    void GenInterfaceDeclaration(const ir::TSInterfaceDeclaration *interfaceDecl);
    void GenClassDeclaration(const ir::ClassDeclaration *classDecl);
    void GenMethodDeclaration(const ir::MethodDefinition *methodDef);
    void GenPropDeclaration(const ir::ClassProperty *classProp);
    void GenGlobalVarDeclaration(const ir::ClassProperty *globalVar);
    void GenLiteral(const ir::Literal *literal);

    template <class T>
    void GenModifier(const T *node, bool isProp = false);
    void GenTypeParameters(const ir::TSTypeParameterDeclaration *typeParams);
    void GenExport(const ir::Identifier *symbol);
    void GenExport(const ir::Identifier *symbol, const std::string &alias);
    void GenDefaultExport(const ir::Identifier *symbol);
    bool ShouldEmitDeclarationSymbol(const ir::Identifier *symbol);

    template <class T, class CB>
    void GenSeparated(const T &container, const CB &cb, const char *separator = ", ", bool isReExport = false);

    void PrepareClassDeclaration(const ir::ClassDefinition *classDef);
    bool ShouldSkipClassDeclaration(const std::string_view &className) const;
    void HandleClassDeclarationTypeInfo(const ir::ClassDefinition *classDef, const std::string_view &className);
    void ProcessClassBody(const ir::ClassDefinition *classDef);
    std::string ReplaceETSGLOBAL(const std::string &typeName);
    std::string GetIndent() const;
    void ProcessIndent();

    void GenGlobalDescriptor();
    void CollectIndirectExportDependencies();
    void ProcessTypeAliasDependencies(const ir::TSTypeAliasDeclaration *typeAliasDecl);
    void ProcessClassDependencies(const ir::ClassDeclaration *classDecl);
    void AddSuperType(const ir::Expression *super);
    void ProcessInterfacesDependencies(const ArenaVector<checker::ETSObjectType *> &interfaces);
    void AddObjectDependencies(const util::StringView &typeName, const std::string &alias = "");
    void GenDeclarations();
    void CloseClassBlock(const bool isDts);

    void EmitClassDeclaration(const ir::ClassDefinition *classDef, const std::string_view &className);
    void EmitClassGlueCode(const ir::ClassDefinition *classDef, const std::string &className);
    void EmitMethodGlueCode(const std::string &methodName, const ir::Identifier *methodIdentifier);
    void EmitPropGlueCode(const ir::ClassProperty *classProp, const std::string &propName);

    void OutDts() {}

    template <class F, class... T>
    void OutDts(F &&first, T &&...rest)
    {
        outputDts_ << first;
        OutDts(std::forward<T>(rest)...);
    }

    void OutTs() {}

    template <class F, class... T>
    void OutTs(F &&first, T &&...rest)
    {
        outputTs_ << first;
        OutTs(std::forward<T>(rest)...);
    }

    void OutEndlDts(const std::size_t count = 1)
    {
        ark::os::file::File::GetEndLine(outputDts_, count);
    }

    void OutEndlTs(const std::size_t count = 1)
    {
        ark::os::file::File::GetEndLine(outputTs_, count);
    }

    void ResetState()
    {
        state_ = GenState();
    }

    struct GenState {
        const ir::Expression *super {nullptr};
        bool inInterface {false};
        bool inGlobalClass {false};
        bool inNamespace {false};
        std::string currentClassDescriptor {};
    } state_ {};

    struct ClassNode {
        bool hasNestedClass {false};
        bool isIndirect {false};
        size_t indentLevel {1};
    } classNode_ {};

    std::stringstream outputDts_;
    std::stringstream outputTs_;
    checker::ETSChecker *checker_ {};
    const ark::es2panda::parser::Program *program_ {};
    util::DiagnosticEngine &diagnosticEngine_;
    ArenaAllocator allocator_;
    ArenaSet<std::string> indirectDependencyObjects_;
    DeclgenOptions declgenOptions_ {};
    std::string globalDesc_;
    ArenaMap<std::string, std::string> typeAliasMap_;
};
}  // namespace ark::es2panda::declgen_ets2ts

#endif  // ES2PANDA_DECLGEN_ETS2TS_H
