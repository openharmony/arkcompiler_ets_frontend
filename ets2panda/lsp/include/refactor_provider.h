/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_LSP_INCLUDE_REFACTOR_PROVIDER_H
#define ES2PANDA_LSP_INCLUDE_REFACTOR_PROVIDER_H

#include "refactors/refactor_types.h"
#include <vector>
#include <memory>
#include <string>

namespace ark::es2panda::lsp {

class RefactorProvider {
public:
    void RegisterRefactor(const std::string &name, std::unique_ptr<Refactor> refactor);
    static RefactorProvider &Instance();
    std::unique_ptr<RefactorEditInfo> GetEditsForRefactor(const RefactorContext &context,
                                                          const std::string &refactorName,
                                                          const std::string &actionName) const;
    std::vector<ApplicableRefactorInfo> GetApplicableRefactors(const RefactorContext &context) const;

    const std::unordered_map<std::string, std::shared_ptr<Refactor>> &GetRefactors() const;

private:
    std::unordered_map<std::string, std::shared_ptr<Refactor>> refactors_;
};

template <typename T>
struct AutoRefactorRegister {
    constexpr explicit AutoRefactorRegister(const std::string &name, std::unique_ptr<T> refactor)
    {
        RefactorProvider::Instance().RegisterRefactor(name, std::move(refactor));
    }

    constexpr explicit AutoRefactorRegister(const std::string &name) : AutoRefactorRegister(name, std::make_unique<T>())
    {
    }
};

}  // namespace ark::es2panda::lsp
#endif  // ES2PANDA_LSP_INCLUDE_REFACTOR_PROVIDER_H
