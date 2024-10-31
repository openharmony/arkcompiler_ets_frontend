/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

// NOTE(ivagin): If ARKTSCONFIG_USE_FILESYSTEM is not defined part of ArkTsConfig functionality is disabled.
//       Only build configuration which prevents us from usage of std::filesystem is "MOBILE" build
//       because of lack of std::filesystem in our current version of mobile nativ development kit.
//       nativ development kit version should be updated and ARKTSCONFIG_USE_FILESYSTEM removed
#if not defined PANDA_TARGET_MOBILE
#define ARKTSCONFIG_USE_FILESYSTEM
#endif

namespace ark::es2panda {

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
        explicit DynamicImportData(Language lang, bool hasDecl) : lang_(lang), hasDecl_(hasDecl) {}

        Language GetLanguage() const
        {
            return lang_;
        }

        bool HasDecl() const
        {
            return hasDecl_;
        }

    private:
        Language lang_;
        bool hasDecl_;
    };

    explicit ArkTsConfig(std::string_view configPath) : configPath_(configPath) {}
    bool Parse();

    std::optional<std::string> ResolvePath(const std::string &path) const;

    std::string ConfigPath() const
    {
        return configPath_;
    }

    std::string BaseUrl() const
    {
        return baseUrl_;
    }
    std::string RootDir() const
    {
        return rootDir_;
    }
    std::string OutDir() const
    {
        return outDir_;
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
        return dynamicPaths_;
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
    static constexpr const char *BASE_URL = "baseUrl";
    static constexpr const char *COMPILER_OPTIONS = "compilerOptions";
    static constexpr const char *EXCLUDE = "exclude";
    static constexpr const char *EXTENDS = "extends";
    static constexpr const char *FILES = "files";
    static constexpr const char *INCLUDE = "include";
    static constexpr const char *OUT_DIR = "outDir";
    static constexpr const char *ROOT_DIR = "rootDir";

    void Inherit(const ArkTsConfig &base);

    bool isParsed_ = false;
    std::string configPath_;

    std::string baseUrl_ {};
    std::string outDir_ {};
    std::string rootDir_ {};
    std::unordered_map<std::string, std::vector<std::string>> paths_ {};
    std::unordered_map<std::string, DynamicImportData> dynamicPaths_ {};
    std::vector<std::string> files_ {};
#ifdef ARKTSCONFIG_USE_FILESYSTEM
    std::vector<Pattern> include_ {};
    std::vector<Pattern> exclude_ {};
#endif  // ARKTSCONFIG_USE_FILESYSTEM
};

// Find source files and compute destination locations
// Return: vector of path pairs <source file, destination abc file>
std::vector<std::pair<std::string, std::string>> FindProjectSources(const std::shared_ptr<ArkTsConfig> &arktsConfig);

std::string JoinPaths(const std::string &a, const std::string &b);
std::string ParentPath(const std::string &path);

}  // namespace ark::es2panda

#endif  // ES2PANDA_AOT_TSCONFIG_H
