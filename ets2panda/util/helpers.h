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

#ifndef ES2PANDA_UTIL_HELPERS_H
#define ES2PANDA_UTIL_HELPERS_H

#include "plugins/ecmascript/es2panda/binder/variableFlags.h"
#include "mem/pool_manager.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"
#include "plugins/ecmascript/es2panda/ir/module/importSpecifier.h"

#include <cmath>
#include <string>

namespace panda::es2panda::binder {
class Variable;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::checker {
class ETSObjectType;
class Type;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::compiler {
class Literal;
}  // namespace panda::es2panda::compiler

namespace panda::es2panda::ir {
class Expression;
class ScriptFunction;
class ClassDefinition;
class ClassProperty;
class Identifier;
class MethodDefinition;
class AstNode;
class ClassStaticBlock;
class TSInterfaceDeclaration;
class TSEnumDeclaration;
class ETSImportDeclaration;
enum class AstNodeType;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::util {
enum class LogLevel : std::uint8_t {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    FATAL,
};

class Helpers {
public:
    Helpers() = delete;

    static bool IsGlobalIdentifier(const util::StringView &str);
    static bool ContainSpreadElement(const ArenaVector<ir::Expression *> &args);
    static util::StringView LiteralToPropName(const ir::Expression *lit);

    template <typename T>
    static bool IsInteger(double number);
    static bool IsIndex(double number);
    static int64_t GetIndex(const util::StringView &str);

    static std::string ToString(double number);
    static util::StringView ToStringView(ArenaAllocator *allocator, double number);
    static util::StringView ToStringView(ArenaAllocator *allocator, int32_t number);
    static util::StringView ToStringView(ArenaAllocator *allocator, uint32_t number);
    static bool IsRelativePath(const std::string &path);

    static const ir::ScriptFunction *GetContainingConstructor(const ir::AstNode *node);
    static const ir::ScriptFunction *GetContainingConstructor(const ir::ClassProperty *node);
    static ir::AstNode *FindAncestorGivenByType(ir::AstNode *node, ir::AstNodeType type);

    static const checker::ETSObjectType *GetContainingObjectType(const ir::AstNode *node);
    static const ir::TSEnumDeclaration *GetContainingEnumDeclaration(const ir::AstNode *node);
    static const ir::ClassDefinition *GetContainingClassDefinition(const ir::AstNode *node);
    static const ir::TSInterfaceDeclaration *GetContainingInterfaceDeclaration(const ir::AstNode *node);
    static const ir::MethodDefinition *GetContainingClassMethodDefinition(const ir::AstNode *node);
    static const ir::ClassStaticBlock *GetContainingClassStaticBlock(const ir::AstNode *node);
    static const ir::ScriptFunction *GetContainingFunction(const ir::AstNode *node);
    static const ir::ClassDefinition *GetClassDefiniton(const ir::ScriptFunction *node);
    static bool IsSpecialPropertyKey(const ir::Expression *expr);
    static bool IsConstantPropertyKey(const ir::Expression *expr, bool is_computed);
    static compiler::Literal ToConstantLiteral(const ir::Expression *expr);
    static bool IsBindingPattern(const ir::AstNode *node);
    static bool IsPattern(const ir::AstNode *node);
    static std::vector<ir::Identifier *> CollectBindingNames(ir::AstNode *node);
    static util::StringView FunctionName(ArenaAllocator *allocator, const ir::ScriptFunction *func);
    static void CheckImportedName(ArenaVector<ir::AstNode *> *specifiers, const ir::ImportSpecifier *specifier,
                                  const std::string &file_name);
    static std::tuple<util::StringView, bool> ParamName(ArenaAllocator *allocator, const ir::AstNode *param,
                                                        uint32_t index);

    template <typename Source, typename Target>
    static bool IsTargetFitInSourceRange(Target target)
    {
        if (!std::isfinite(target)) {
            return true;
        }

        // NOLINTNEXTLINE(misc-redundant-expression)
        return target >= std::numeric_limits<Source>::lowest() &&
               target <= static_cast<Target>(std::numeric_limits<Source>::max());
    }

    static const uint32_t INVALID_INDEX = 4294967295L;

    static std::string CreateEscapedString(const std::string &str);
    static std::string UTF16toUTF8(char16_t c);

    template <typename... Elements>
    static void LogDebug(Elements &&...elems);
    template <typename... Elements>
    static void LogInfo(Elements &&...elems);
    template <typename... Elements>
    static void LogWarning(Elements &&...elems);
    template <typename... Elements>
    static void LogError(Elements &&...elems);
    template <typename... Elements>
    static void LogFatal(Elements &&...elems);

    template <typename... Elements>
    static std::string AppendAll(Elements &&...elems);

    static bool IsDynamicModuleVariable(const binder::Variable *var);
    static bool IsDynamicNamespaceVariable(const binder::Variable *var);
    static const ir::ETSImportDeclaration *ImportDeclarationForDynamicVar(const binder::Variable *var);

    static std::pair<std::string_view, std::string_view> SplitSignature(std::string_view signature);

private:
    template <LogLevel LOG_L, typename... Elements>
    static void Log(Elements &&...elems);
};

template <typename T>
bool Helpers::IsInteger(double number)
{
    if (std::fabs(number) <= static_cast<double>(std::numeric_limits<T>::max())) {
        T int_num = static_cast<T>(number);

        if (static_cast<double>(int_num) == number) {
            return true;
        }
    }

    return false;
}

template <LogLevel LOG_L, typename... Elements>
void Helpers::Log(Elements &&...elems)
{
    constexpr auto ES2PANDA = panda::Logger::Component::ES2PANDA;
    constexpr auto LOG_LEVEL = []() {
        switch (LOG_L) {
            case LogLevel::DEBUG: {
                return panda::Logger::Level::DEBUG;
            }
            case LogLevel::INFO: {
                return panda::Logger::Level::INFO;
            }
            case LogLevel::WARNING: {
                return panda::Logger::Level::WARNING;
            }
            case LogLevel::ERROR: {
                return panda::Logger::Level::ERROR;
            }
            case LogLevel::FATAL: {
                return panda::Logger::Level::FATAL;
            }
            default: {
                UNREACHABLE_CONSTEXPR();
            }
        }
    }();

#ifndef NDEBUG
    const bool is_message_suppressed = panda::Logger::IsMessageSuppressed(LOG_LEVEL, ES2PANDA);
#else
    const bool is_message_suppressed = false;
#endif
    if (!panda::Logger::IsLoggingOnOrAbort(LOG_LEVEL, ES2PANDA) || is_message_suppressed) {
        return;
    }

    (panda::Logger::Message(LOG_LEVEL, ES2PANDA, false).GetStream() << ... << std::forward<Elements>(elems));
}

template <typename... Elements>
void Helpers::LogDebug(Elements &&...elems)
{
    Helpers::Log<LogLevel::DEBUG>(std::forward<Elements>(elems)...);
}

template <typename... Elements>
void Helpers::LogInfo(Elements &&...elems)
{
    Helpers::Log<LogLevel::INFO>(std::forward<Elements>(elems)...);
}

template <typename... Elements>
void Helpers::LogWarning(Elements &&...elems)
{
    Helpers::Log<LogLevel::WARNING>(std::forward<Elements>(elems)...);
}

template <typename... Elements>
void Helpers::LogError(Elements &&...elems)
{
    Helpers::Log<LogLevel::ERROR>(std::forward<Elements>(elems)...);
}

template <typename... Elements>
void Helpers::LogFatal(Elements &&...elems)
{
    Helpers::Log<LogLevel::FATAL>(std::forward<Elements>(elems)...);
}

template <typename... Elements>
std::string Helpers::AppendAll(Elements &&...elems)
{
    std::string ret {};
    ((ret += std::forward<Elements>(elems)), ...);
    return ret;
}

}  // namespace panda::es2panda::util

#endif
