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

#ifndef ES2PANDA_PARSER_CORE_ETS_PARSER_TEMPLATES_H
#define ES2PANDA_PARSER_CORE_ETS_PARSER_TEMPLATES_H

template <typename T>
void SetFormattingFileName(T &&fileName)
{
    GetContext().SetFormattingFileName(std::forward<T>(fileName));
}

template <typename T>
void ProcessFormattedArg(std::vector<ir::AstNode *> &nodes, T &&arg)
{
    if constexpr (std::is_convertible_v<std::decay_t<T>, ir::AstNode *>) {
        nodes.emplace_back(std::forward<T>(arg));
    } else if constexpr (std::is_same_v<std::decay_t<T>, util::StringView>) {
        nodes.emplace_back(AllocNode<ir::Identifier>(std::forward<T>(arg), Allocator()));
    } else if constexpr (std::is_same_v<std::decay_t<T>, util::UString>) {
        nodes.emplace_back(AllocNode<ir::Identifier>(arg.View(), Allocator()));
    } else if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
        nodes.emplace_back(
            AllocNode<ir::Identifier>(util::UString(std::forward<T>(arg), Allocator()).View(), Allocator()));
    } else if constexpr (std::is_constructible_v<std::string, std::decay_t<T>>) {
        nodes.emplace_back(AllocNode<ir::Identifier>(
            util::UString(std::string {std::forward<T>(arg)}, Allocator()).View(), Allocator()));
    } else if constexpr (std::is_convertible_v<std::decay_t<T>, checker::Type *>) {
        nodes.emplace_back(AllocNode<ir::OpaqueTypeNode>(std::forward<T>(arg), Allocator()));
    } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<ir::AstNode *>>) {
        nodes.emplace_back(AllocNode<ir::TSInterfaceBody>(std::forward<T>(arg)));
    } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<ir::Expression *>>) {
        nodes.emplace_back(AllocNode<ir::SequenceExpression>(std::forward<T>(arg)));
    } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<ir::Statement *>>) {
        nodes.emplace_back(AllocNode<ir::BlockExpression>(std::forward<T>(arg)));
    } else if constexpr (std::is_same_v<std::decay_t<T>, ArenaVector<checker::Type *>>) {
        for (auto *type : arg) {
            nodes.emplace_back(AllocNode<ir::OpaqueTypeNode>(type, Allocator()));
        }
    } else {
        static_assert(STATIC_FALSE<T>, "Format argument has invalid type.");
    }
}

template <typename... Args>
ir::Expression *CreateFormattedExpression(std::string_view const sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedExpression(sourceCode, insertingNodes);
}

template <typename... Args>
ArenaVector<ir::Statement *> CreateFormattedStatements(std::string_view const sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedStatements(sourceCode, insertingNodes);
}

template <typename... Args>
ir::Statement *CreateFormattedClassDeclaration(std::string_view sourceCode, bool allowStatic, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedClassDeclaration(sourceCode, insertingNodes, allowStatic);
}

template <typename... Args>
ir::AstNode *CreateFormattedClassElement(std::string_view sourceCode, ir::ClassDefinition *classDefinition,
                                         Args &&...args)
{
    return CreateFormattedClassElement(sourceCode, classDefinition->Body(), classDefinition->Modifiers(),
                                       std::forward<Args...>(args...));
}

template <typename... Args>
ir::AstNode *CreateFormattedClassFieldDefinition(std::string_view const sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedClassFieldDefinition(sourceCode, insertingNodes);
}

template <typename... Args>
ir::AstNode *CreateFormattedClassElement(std::string_view sourceCode, const ArenaVector<ir::AstNode *> &properties,
                                         ir::ClassDefinitionModifiers modifiers, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedClassElement(sourceCode, insertingNodes, properties, modifiers);
}

template <typename... Args>
ir::AstNode *CreateFormattedClassMethodDefinition(std::string_view const sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedClassMethodDefinition(sourceCode, insertingNodes);
}

template <typename... Args>
ir::Statement *CreateFormattedTopLevelStatement(std::string_view sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedTopLevelStatement(sourceCode, insertingNodes);
}

template <typename... Args>
ir::TypeNode *CreateFormattedTypeAnnotation(std::string_view const sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedTypeAnnotation(sourceCode, insertingNodes);
}

template <typename... Args>
ir::Statement *CreateFormattedStatement(std::string_view const sourceCode, Args &&...args)
{
    std::vector<ir::AstNode *> insertingNodes {};
    insertingNodes.reserve(sizeof...(Args));
    (ProcessFormattedArg(insertingNodes, std::forward<Args>(args)), ...);
    return CreateFormattedStatement(sourceCode, insertingNodes);
}

#endif
