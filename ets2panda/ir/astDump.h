/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_AST_DUMP_H
#define ES2PANDA_IR_AST_DUMP_H

#include "ir/astNode.h"
#include "lexer/token/sourceLocation.h"
#include "lexer/token/tokenType.h"
#include "lexer/token/number.h"
#include "util/ustring.h"

#include <sstream>
#include <variant>

namespace ark::es2panda::ir {
class AstDumper {
public:
    class Nullish {
    public:
        explicit Nullish(const ir::AstNode *node) : node_(node) {}

        const ir::AstNode *Node() const
        {
            return node_;
        }

    private:
        const ir::AstNode *node_;
    };

    class Optional {
    public:
        using Val = std::variant<const char *, const AstNode *, bool, std::vector<const AstNode *>>;
        explicit Optional(const ir::AstNode *node) : value_(node) {}
        explicit Optional(const char *string) : value_(const_cast<char *>(string)) {}
        explicit Optional(bool boolean) : value_(boolean) {}

        template <typename T>
        explicit Optional(const ArenaVector<T> &array)
        {
            std::vector<const AstNode *> nodes;
            nodes.reserve(array.size());

            for (auto &it : array) {
                nodes.push_back(it);
            }

            value_ = std::move(nodes);
        }

        const Val &Value() const
        {
            return value_;
        }

    private:
        Val value_;
    };

    class Property {
    public:
        class Ignore {
        public:
            Ignore() = default;
        };

        enum class Constant {
            PROP_NULL,
            PROP_UNDEFINED,
            EMPTY_ARRAY,
        };

        using Val = std::variant<const char *, lexer::TokenType, std::initializer_list<Property>, util::StringView,
                                 bool, char16_t, lexer::Number, const ir::AstNode *, std::vector<const ir::AstNode *>,
                                 Constant, Nullish, Ignore>;

        Property(const char *key, const char *string) : key_(key), value_(string) {}
        Property(const char *key, util::StringView str) : key_(key), value_(str) {}
        Property(const char *key, bool boolean) : key_(key), value_(boolean) {}
        Property(const char *key, char16_t c16) : key_(key), value_(c16) {}
        Property(const char *key, lexer::Number number) : key_(key), value_(number) {}
        Property(const char *key, lexer::TokenType token) : key_(key), value_(token) {}
        Property(const char *key, std::initializer_list<Property> props) : key_(key), value_(props) {}
        Property(const char *key, const ir::AstNode *node) : key_(key), value_(const_cast<ir::AstNode *>(node)) {}

        Property(const char *key, Constant constant) : key_(key), value_(constant) {}
        Property(const char *key, Nullish nullish) : key_(key)
        {
            if (nullish.Node() != nullptr) {
                value_ = nullish.Node();
            } else {
                value_ = Property::Constant::PROP_NULL;
            }
        }

        Property(const char *key, const Optional &optional) : key_(key)
        {
            const auto &value = optional.Value();
            if (std::holds_alternative<const ir::AstNode *>(value) &&
                (std::get<const ir::AstNode *>(value) != nullptr)) {
                value_ = std::get<const ir::AstNode *>(value);
                return;
            }

            if (std::holds_alternative<const char *>(value) && (std::get<const char *>(value) != nullptr)) {
                value_ = std::get<const char *>(value);
                return;
            }

            if (std::holds_alternative<bool>(value) && std::get<bool>(value)) {
                value_ = std::get<bool>(value);
                return;
            }

            if (std::holds_alternative<std::vector<const AstNode *>>(value)) {
                const auto &array = std::get<std::vector<const AstNode *>>(value);
                if (!array.empty()) {
                    value_ = array;
                    return;
                }
            }

            value_ = Ignore();
        }

        template <typename T>
        Property(const char *key, const ArenaVector<T> &array) : key_(key)
        {
            if (array.empty()) {
                value_ = Constant::EMPTY_ARRAY;
                return;
            }

            std::vector<const ir::AstNode *> nodes;
            nodes.reserve(array.size());

            for (auto &it : array) {
                nodes.push_back(it);
            }

            value_ = std::move(nodes);
        }

        template <typename T>
        Property(const char *key, const ArenaVector<T> &array, const std::function<bool(AstNode *)> &filter) : key_(key)
        {
            std::vector<const ir::AstNode *> nodes;
            nodes.reserve(array.size());

            for (auto &it : array) {
                if (filter(it)) {
                    nodes.push_back(it);
                }
            }

            if (nodes.empty()) {
                value_ = Constant::EMPTY_ARRAY;
                return;
            }

            value_ = std::move(nodes);
        }

        const char *Key() const
        {
            return key_;
        }

        const Val &Value() const
        {
            return value_;
        }

    private:
        const char *key_;
        Val value_ {};
    };

    explicit AstDumper(const ir::AstNode *node, util::StringView sourceCode = "");

    void Add(std::initializer_list<Property> props);
    void Add(const AstDumper::Property &prop);

    static const char *ModifierToString(ModifierFlags flags);
    static const char *TypeOperatorToString(TSOperatorType operatorType);

    std::string Str() const
    {
        return ss_.str();
    }

private:
    using WrapperCb = std::function<void()>;

    template <typename T>
    void AddList(T props)
    {
        for (auto it = props.begin(); it != props.end();) {
            Serialize(*it);

            do {
                if (++it == props.end()) {
                    return;
                }
            } while (std::holds_alternative<Property::Ignore>((*it).Value()));

            ss_ << ',';
        }
    }

    void Indent();

    void Serialize(const AstDumper::Property &prop);
    void SerializePropKey(const char *str);
    void SerializeString(const char *str);
    void SerializeString(const util::StringView &str);
    void SerializeNumber(size_t number);
    void SerializeNumber(lexer::Number number);
    void SerializeChar16(char16_t c16);
    void SerializeBoolean(bool boolean);
    void SerializeObject(const ir::AstNode *object);
    void SerializeToken(lexer::TokenType token);
    void SerializePropList(std::initializer_list<AstDumper::Property> props);
    void SerializeConstant(Property::Constant constant);
    void Wrap(const WrapperCb &cb, char delimStart = '{', char delimEnd = '}');

    void SerializeLoc(const lexer::SourceRange &loc);
    void SerializeSourcePosition(const lexer::SourcePosition &pos);

    void SerializeArray(std::vector<const ir::AstNode *> array);

    const lexer::LineIndex index_;
    std::stringstream ss_;
    int32_t indent_ {};
    bool isSrcEmpty_ = false;
};
}  // namespace ark::es2panda::ir

#endif  // AST_DUMP_H
