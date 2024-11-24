/**
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

#include "ambientLowering.h"
#include <string_view>

#include "ir/expressions/dummyNode.h"
#include "ir/astNode.h"

namespace ark::es2panda::compiler {
std::string_view AmbientLowering::Name() const
{
    static std::string const NAME = "AmbientLowering";
    return NAME;
}

bool AmbientLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }

    return !program->Ast()->IsAnyChild(
        [](const ir::AstNode *node) -> bool { return node->IsDummyNode() && node->AsDummyNode()->IsDeclareIndexer(); });
}

bool AmbientLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            Perform(ctx, extProg);
        }
    }

    // Generate $_get and $_set for ambient Indexer
    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [this, ctx](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsClassDefinition()) {
                return CreateIndexerMethodIfNeeded(ast->AsClassDefinition(), ctx);
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

    auto const indexName = node->GetIndexName();
    auto const returnType = node->GetReturnTypeLiteral()->AsETSTypeReferencePart()->Name()->AsIdentifier()->Name();
    std::string sourceCode;
    if (funcKind == ir::MethodDefinitionKind::GET) {
        sourceCode = "$_get(" + std::string(indexName) + " : number) : " + std::string(returnType);
    } else if (funcKind == ir::MethodDefinitionKind::SET) {
        sourceCode =
            "$_set(" + std::string(indexName) + " : number, " + "value : " + std::string(returnType) + " ) : void";
    } else {
        UNREACHABLE();
    }

    auto methodDefinition = parser->CreateFormattedClassMethodDefinition(sourceCode);

    methodDefinition->SetRange(node->Range());
    methodDefinition->SetParent(node->Parent());
    methodDefinition->AddModifier(ir::ModifierFlags::DECLARE);
    methodDefinition->AsMethodDefinition()->Function()->AddModifier(ir::ModifierFlags::DECLARE);
    return methodDefinition->AsMethodDefinition();
}

ir::ClassDefinition *AmbientLowering::CreateIndexerMethodIfNeeded(ir::ClassDefinition *classDef,
                                                                  public_lib::Context *ctx)
{
    auto &classBody = classDef->Body();
    auto it = classBody.begin();
    // Only one DummyNode is allowed in classBody for now
    ASSERT(std::count_if(classBody.begin(), classBody.end(), [](ir::AstNode *node) { return node->IsDummyNode(); }) <=
           1);
    while (it != classBody.end()) {
        if ((*it)->IsDummyNode() && (*it)->AsDummyNode()->IsDeclareIndexer()) {
            auto setDefinition =
                CreateMethodFunctionDefinition((*it)->AsDummyNode(), ctx, ir::MethodDefinitionKind::SET);
            auto getDefinition =
                CreateMethodFunctionDefinition((*it)->AsDummyNode(), ctx, ir::MethodDefinitionKind::GET);

            classBody.erase(it);
            classBody.emplace_back(setDefinition);
            classBody.emplace_back(getDefinition);
            break;
        }
        ++it;
    }

    return classDef;
}
}  // namespace ark::es2panda::compiler
