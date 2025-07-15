/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ambientLowering.h"
#include <string_view>

#include "ir/expressions/dummyNode.h"
#include "ir/astNode.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::compiler {
std::string_view AmbientLowering::Name() const
{
    static std::string const NAME = "AmbientLowering";
    return NAME;
}

bool AmbientLowering::PostconditionForModule([[maybe_unused]] public_lib::Context *ctx, const parser::Program *program)
{
    return !program->Ast()->IsAnyChild(
        [](const ir::AstNode *node) -> bool { return node->IsDummyNode() && node->AsDummyNode()->IsDeclareIndexer(); });
}

bool AmbientLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    // Generate $_get and $_set for ambient Indexer
    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [this, ctx](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsClassDefinition()) {
                return CreateIndexerMethodIfNeeded(ast->AsClassDefinition(), ctx);
            }
            if (ast->IsTSInterfaceBody()) {
                return CreateIndexerMethodIfNeeded(ast->AsTSInterfaceBody(), ctx);
            }
            return ast;
        },
        Name());

    return true;
}

ir::MethodDefinition *CreateMethodFunctionDefinition(ir::DummyNode *node, public_lib::Context *ctx,
                                                     ir::MethodDefinitionKind funcKind)
{
    auto parser = ctx->parser->AsETSParser();

    auto indexName = node->GetIndexName();
    auto const returnType = node->GetReturnTypeLiteral()->AsETSTypeReferencePart()->GetIdent();
    if (returnType->IsErrorPlaceHolder()) {
        return nullptr;
    }
    if (indexName == ERROR_LITERAL) {
        indexName = "_";
    }
    std::string sourceCode;
    if (funcKind == ir::MethodDefinitionKind::GET) {
        sourceCode = "$_get(" + std::string(indexName) + " : number) : " + std::string(returnType->Name());
    } else if (funcKind == ir::MethodDefinitionKind::SET) {
        sourceCode = "$_set(" + std::string(indexName) + " : number, " + "value : " + std::string(returnType->Name()) +
                     " ) : void";
    } else {
        ES2PANDA_UNREACHABLE();
    }

    auto methodDefinition = parser->CreateFormattedClassMethodDefinition(sourceCode);

    // NOTE(kaskov): #23399 It is temporary solution, we set default SourcePosition in all nodes in generated code
    compiler::SetSourceRangesRecursively(methodDefinition, node->Range());

    methodDefinition->SetParent(node->Parent());
    methodDefinition->AddModifier(ir::ModifierFlags::DECLARE);
    ES2PANDA_ASSERT(methodDefinition->AsMethodDefinition()->Function() != nullptr);
    methodDefinition->AsMethodDefinition()->Function()->AddModifier(ir::ModifierFlags::DECLARE);
    return methodDefinition->AsMethodDefinition();
}

ir::AstNode *AmbientLowering::CreateIndexerMethodIfNeeded(ir::AstNode *ast, public_lib::Context *ctx)
{
    if (!ast->IsClassDefinition() && !ast->IsTSInterfaceBody()) {
        return ast;
    }

    ArenaVector<ir::AstNode *> &classBody =
        ast->IsClassDefinition() ? ast->AsClassDefinition()->Body() : ast->AsTSInterfaceBody()->Body();

    auto it = classBody.begin();
    // Only one DummyNode is allowed in classBody for now
    ES2PANDA_ASSERT(
        std::count_if(classBody.begin(), classBody.end(), [](ir::AstNode *node) { return node->IsDummyNode(); }) <= 1);
    while (it != classBody.end()) {
        if ((*it)->IsDummyNode() && (*it)->AsDummyNode()->IsDeclareIndexer()) {
            auto setDefinition =
                CreateMethodFunctionDefinition((*it)->AsDummyNode(), ctx, ir::MethodDefinitionKind::SET);
            auto getDefinition =
                CreateMethodFunctionDefinition((*it)->AsDummyNode(), ctx, ir::MethodDefinitionKind::GET);

            classBody.erase(it);
            if (setDefinition != nullptr && getDefinition != nullptr) {
                classBody.emplace_back(getDefinition);
                classBody.emplace_back(setDefinition);
            }
            break;
        }
        ++it;
    }

    return ast;
}
}  // namespace ark::es2panda::compiler
