/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator.staticTS;

import org.eclipse.jdt.core.compiler.IProblem;

import java.util.List;

public class SyntaxCheckException extends Exception {

    private static String buildErrorMessage(List<String> parseProblems) {
            StringBuilder sb = new StringBuilder();
            for( String problem: parseProblems) {
                sb.append(problem).append('\n');
            }
            return sb.toString();
    }

    public SyntaxCheckException(List<String> parseProblems) { this(buildErrorMessage(parseProblems)); }

    public SyntaxCheckException(String s) { super(s); }
}
