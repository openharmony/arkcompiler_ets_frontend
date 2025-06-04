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

#ifndef ES2PANDA_LSP_USER_PREFERENCES_H
#define ES2PANDA_LSP_USER_PREFERENCES_H

#include <string>

namespace ark::es2panda::lsp {
class UserPreferences {
public:
    /**
     *  @brief Quote preference options
     *
     * AUTO   - Let the editor decide based on context
     * DOUBLE - Always use double quotes (")
     * SINGLE - Always use single quotes (')
     */
    enum class QuotePreference { AUTO, DOUBLE, SINGLE };

    /**
     * @brief Controls the automatic imports
     *
     * AUTO - Automatically determine whether to include imports based on project context
     * ON   - Always include automatic imports
     * OFF  - Never include automatic imports
     */
    enum class IncludePackageJsonAutoImports { AUTO, ON, OFF };

    /**
     * @brief Controls the display of parameter name hints in function calls
     *
     * NONE      - No parameter name hints shown
     * LITERALS  - Show parameter hints only for literal arguments
     * ALL       - Show parameter hints for all arguments
     */
    enum class IncludeInlayParameterNameHints { NONE, LITERALS, ALL };

    /**
     * @brief Determines how module import paths are specified
     *
     * SHORTEST          - Use the shortest possible path
     * PROJECT_RELATIVE  - Use paths relative to the project root
     * RELATIVE          - Use paths relative to the current file
     * NON_RELATIVE      - Use absolute paths
     */
    enum class ImportModuleSpecifierPreference { SHORTEST, PROJECT_RELATIVE, RELATIVE, NON_RELATIVE };

    /**
     * @brief Controls the file extension style in import statements
     *
     * AUTO     - Automatically determine the appropriate ending
     * MINIMAL  - Omit extension when possible
     * INDEX    - Include '/index' in paths
     * JS       - Include '.js' extension
     */
    enum class ImportModuleSpecifierEnding { AUTO, MINIMAL, INDEX, JS };

private:
    QuotePreference quotePreference_ = QuotePreference::AUTO;
    IncludePackageJsonAutoImports includePackageJsonAutoImports_ = IncludePackageJsonAutoImports::AUTO;
    IncludeInlayParameterNameHints includeInlayParameterNameHints_ = IncludeInlayParameterNameHints::NONE;
    ImportModuleSpecifierPreference importModuleSpecifierPreference_ = ImportModuleSpecifierPreference::SHORTEST;
    ImportModuleSpecifierEnding importModuleSpecifierEnding_ = ImportModuleSpecifierEnding::AUTO;
    std::string autoImportFileExcludePatterns_;
    bool disableSuggestions_ = false;
    bool includeCompletionsForModuleExports_ = false;
    bool includeCompletionsForImportStatements_ = false;
    bool includeCompletionsWithSnippetText_ = false;
    bool includeCompletionsChainCompletions_ = false;
    bool includeCompletionsWithInsertText_ = false;
    bool includeCompletionsClassMemberSnippets_ = false;
    bool includeCompletionsWithObjectLiteralMethodSnippets_ = false;
    bool useLabelDetailsIncompletionsEntries_ = false;
    bool allowIncompleteCompletions_ = false;
    bool allowTextChangesInNewFiles_ = false;
    bool providePrefixAndSuffixTextForRename_ = false;
    bool provideRefactorNotApplicableReason_ = false;
    bool includeInlayParameterNameHintsWhenArgumentMatchesName_ = false;
    bool includeInlayFunctionParameterTypeHints_ = false;
    bool includeInlayVariableTypeHints_ = false;
    bool includeInlayVariableTypeHintsWhenTypeMatchesName_ = false;
    bool includeInlayPropertyDeclarationTypeHints_ = false;
    bool includeInlayFunctionLikeReturnTypeHints_ = false;
    bool includeInlayEnumMemberValueHints_ = false;
    bool allowRenameOfImportPath_ = false;

public:
    /*default preferences*/
    static UserPreferences GetDefaultUserPreferences()
    {
        return UserPreferences();
    }

    /*current preferences*/
    UserPreferences *GetUserPreferences()
    {
        return this;
    }

    // Setters for enum types
    void SetQuotePreference(QuotePreference value)
    {
        quotePreference_ = value;
    }

    void SetIncludePackageJsonAutoImports(IncludePackageJsonAutoImports value)
    {
        includePackageJsonAutoImports_ = value;
    }

    void SetIncludeInlayParameterNameHints(IncludeInlayParameterNameHints value)
    {
        includeInlayParameterNameHints_ = value;
    }

    void SetImportModuleSpecifierPreference(ImportModuleSpecifierPreference value)
    {
        importModuleSpecifierPreference_ = value;
    }

    void SetImportModuleSpecifierEnding(ImportModuleSpecifierEnding value)
    {
        importModuleSpecifierEnding_ = value;
    }

    void SetAutoImportFileExcludePatterns(const std::string &patterns)
    {
        autoImportFileExcludePatterns_ = patterns;
    }

    // Setters for boolean values
    void SetDisableSuggestions(bool value)
    {
        disableSuggestions_ = value;
    }

    void SetIncludeCompletionsForModuleExports(bool value)
    {
        includeCompletionsForModuleExports_ = value;
    }

    void SetIncludeCompletionsForImportStatements(bool value)
    {
        includeCompletionsForImportStatements_ = value;
    }

    void SetIncludeCompletionsWithSnippetText(bool value)
    {
        includeCompletionsWithSnippetText_ = value;
    }

    void SetIncludeCompletionsChainCompletions(bool value)
    {
        includeCompletionsChainCompletions_ = value;
    }

    void SetIncludeCompletionsWithInsertText(bool value)
    {
        includeCompletionsWithInsertText_ = value;
    }

    void SetIncludeCompletionsClassMemberSnippets(bool value)
    {
        includeCompletionsClassMemberSnippets_ = value;
    }

    void SetIncludeCompletionsWithObjectLiteralMethodSnippets(bool value)
    {
        includeCompletionsWithObjectLiteralMethodSnippets_ = value;
    }

    void SetUseLabelDetailsIncompletionsEntries(bool value)
    {
        useLabelDetailsIncompletionsEntries_ = value;
    }

    void SetAllowIncompleteCompletions(bool value)
    {
        allowIncompleteCompletions_ = value;
    }

    void SetAllowTextChangesInNewFiles(bool value)
    {
        allowTextChangesInNewFiles_ = value;
    }

    void SetProvidePrefixAndSuffixTextForRename(bool value)
    {
        providePrefixAndSuffixTextForRename_ = value;
    }

    void SetProvideRefactorNotApplicableReason(bool value)
    {
        provideRefactorNotApplicableReason_ = value;
    }

    void SetIncludeInlayParameterNameHintsWhenArgumentMatchesName(bool value)
    {
        includeInlayParameterNameHintsWhenArgumentMatchesName_ = value;
    }

    void SetIncludeInlayFunctionParameterTypeHints(bool value)
    {
        includeInlayFunctionParameterTypeHints_ = value;
    }

    void SetIncludeInlayVariableTypeHints(bool value)
    {
        includeInlayVariableTypeHints_ = value;
    }

    void SetIncludeInlayVariableTypeHintsWhenTypeMatchesName(bool value)
    {
        includeInlayVariableTypeHintsWhenTypeMatchesName_ = value;
    }

    void SetIncludeInlayPropertyDeclarationTypeHints(bool value)
    {
        includeInlayPropertyDeclarationTypeHints_ = value;
    }

    void SetIncludeInlayFunctionLikeReturnTypeHints(bool value)
    {
        includeInlayFunctionLikeReturnTypeHints_ = value;
    }

    void SetIncludeInlayEnumMemberValueHints(bool value)
    {
        includeInlayEnumMemberValueHints_ = value;
    }

    void SetAllowRenameOfImportPath(bool value)
    {
        allowRenameOfImportPath_ = value;
    }

    QuotePreference GetQuotePreference() const
    {
        return quotePreference_;
    }

    IncludePackageJsonAutoImports GetIncludePackageJsonAutoImports() const
    {
        return includePackageJsonAutoImports_;
    }

    IncludeInlayParameterNameHints GetIncludeInlayParameterNameHints() const
    {
        return includeInlayParameterNameHints_;
    }

    ImportModuleSpecifierPreference GetImportModuleSpecifierPreference() const
    {
        return importModuleSpecifierPreference_;
    }

    ImportModuleSpecifierEnding GetImportModuleSpecifierEnding() const
    {
        return importModuleSpecifierEnding_;
    }

    std::string GetAutoImportFileExcludePatterns() const
    {
        return autoImportFileExcludePatterns_;
    }

    bool GetDisableSuggestions() const
    {
        return disableSuggestions_;
    }

    bool GetIncludeCompletionsForModuleExports() const
    {
        return includeCompletionsForModuleExports_;
    }

    bool GetIncludeCompletionsForImportStatements() const
    {
        return includeCompletionsForImportStatements_;
    }

    bool GetIncludeCompletionsWithSnippetText() const
    {
        return includeCompletionsWithSnippetText_;
    }

    bool GetIncludeCompletionsChainCompletions() const
    {
        return includeCompletionsChainCompletions_;
    }

    bool GetIncludeCompletionsWithInsertText() const
    {
        return includeCompletionsWithInsertText_;
    }

    bool GetIncludeCompletionsClassMemberSnippets() const
    {
        return includeCompletionsClassMemberSnippets_;
    }

    bool GetIncludeCompletionsWithObjectLiteralMethodSnippets() const
    {
        return includeCompletionsWithObjectLiteralMethodSnippets_;
    }

    bool GetUseLabelDetailsIncompletionsEntries() const
    {
        return useLabelDetailsIncompletionsEntries_;
    }

    bool GetAllowIncompleteCompletions() const
    {
        return allowIncompleteCompletions_;
    }

    bool GetAllowTextChangesInNewFiles() const
    {
        return allowTextChangesInNewFiles_;
    }

    bool GetProvidePrefixAndSuffixTextForRename() const
    {
        return providePrefixAndSuffixTextForRename_;
    }

    bool GetProvideRefactorNotApplicableReason() const
    {
        return provideRefactorNotApplicableReason_;
    }

    bool GetIncludeInlayParameterNameHintsWhenArgumentMatchesName() const
    {
        return includeInlayParameterNameHintsWhenArgumentMatchesName_;
    }

    bool GetIncludeInlayFunctionParameterTypeHints() const
    {
        return includeInlayFunctionParameterTypeHints_;
    }

    bool GetIncludeInlayVariableTypeHints() const
    {
        return includeInlayVariableTypeHints_;
    }

    bool GetIncludeInlayVariableTypeHintsWhenTypeMatchesName() const
    {
        return includeInlayVariableTypeHintsWhenTypeMatchesName_;
    }

    bool GetIncludeInlayPropertyDeclarationTypeHints() const
    {
        return includeInlayPropertyDeclarationTypeHints_;
    }

    bool GetIncludeInlayFunctionLikeReturnTypeHints() const
    {
        return includeInlayFunctionLikeReturnTypeHints_;
    }

    bool GetIncludeInlayEnumMemberValueHints() const
    {
        return includeInlayEnumMemberValueHints_;
    }

    bool GetAllowRenameOfImportPath() const
    {
        return allowRenameOfImportPath_;
    }
};

}  // namespace ark::es2panda::lsp

#endif