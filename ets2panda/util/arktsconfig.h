/**
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_AOT_ARKTSCONFIG_H
#define ES2PANDA_AOT_ARKTSCONFIG_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "util/language.h"

// TODO(ivagin): If ARKTSCONFIG_USE_FILESYSTEM is not defined part of ArkTsConfig functionality is disabled.
//       Only build configuration which prevents us from usage of std::filesystem is "MOBILE" build
//       because of lack of std::filesystem in our current version of mobile NDK.
//       NDK version should be updated and ARKTSCONFIG_USE_FILESYSTEM removed
#if not defined PANDA_TARGET_MOBILE
#define ARKTSCONFIG_USE_FILESYSTEM
#endif

namespace panda::es2panda {

class ArkTsConfig {
public:
#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Pattern describes arktsconfig path pattern for 'include' or 'exclude' properties
    // e.g. src/**, src/**/*, src/util?.ts
    class Pattern {
    public:
        Pattern() = default;
        Pattern(std::string value, std::string base);

        bool IsPattern() const;

        // Get root from which sources file search should be started
        // e.g. src/** -> src; src/index?.ts -> src; src/component/*/index.ts -> src/component; src/index* -> src/
        std::string GetSearchRoot() const;

        // Test if absolute path is matched by pattern
        bool Match(const std::string &path) const;

    private:
        std::string value_ {};
        std::string base_ {};
    };
#endif  // ARKTSCONFIG_USE_FILESYSTEM

    class DynamicImportData {
    public:
        explicit DynamicImportData(Language lang, bool has_decl) : lang_(lang), has_decl_(has_decl) {}

        Language GetLanguage() const
        {
            return lang_;
        }

        bool HasDecl() const
        {
            return has_decl_;
        }

    private:
        Language lang_;
        bool has_decl_;
    };

    explicit ArkTsConfig(std::string config_path) : config_path_(std::move(config_path)) {}
    bool Parse();

    std::string ResolvePath(const std::string &path);

    std::string ConfigPath() const
    {
        return config_path_;
    }

    std::string BaseUrl() const
    {
        return base_url_;
    }
    std::string RootDir() const
    {
        return root_dir_;
    }
    std::string OutDir() const
    {
        return out_dir_;
    }
    const std::vector<std::string> &Files() const
    {
        return files_;
    }
    const std::unordered_map<std::string, std::vector<std::string>> &Paths() const
    {
        return paths_;
    }
    const std::unordered_map<std::string, DynamicImportData> &DynamicPaths() const
    {
        return dynamic_paths_;
    }
#ifdef ARKTSCONFIG_USE_FILESYSTEM
    const std::vector<Pattern> &Include() const
    {
        return include_;
    }
    const std::vector<Pattern> &Exclude() const
    {
        return exclude_;
    }
#endif  // ARKTSCONFIG_USE_FILESYSTEM

private:
    void Inherit(const ArkTsConfig &base);

    bool is_parsed_ = false;
    std::string config_path_;

    std::string base_url_ {};
    std::string out_dir_ {};
    std::string root_dir_ {};
    std::unordered_map<std::string, std::vector<std::string>> paths_ {};
    std::unordered_map<std::string, DynamicImportData> dynamic_paths_ {};
    std::vector<std::string> files_ {};
#ifdef ARKTSCONFIG_USE_FILESYSTEM
    std::vector<Pattern> include_ {};
    std::vector<Pattern> exclude_ {};
#endif  // ARKTSCONFIG_USE_FILESYSTEM
};

// Find source files and compute destination locations
// Return: vector of path pairs <source file, destination abc file>
std::vector<std::pair<std::string, std::string>> FindProjectSources(const std::shared_ptr<ArkTsConfig> &arkts_config);
}  // namespace panda::es2panda

#endif  // ES2PANDA_AOT_TSCONFIG_H
