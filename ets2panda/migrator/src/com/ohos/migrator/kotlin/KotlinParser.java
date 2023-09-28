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

package com.ohos.migrator.kotlin;

import com.ohos.migrator.util.FileUtils;
import com.intellij.openapi.project.Project;
import com.intellij.psi.PsiManager;
import com.intellij.testFramework.LightVirtualFile;
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment;
import org.jetbrains.kotlin.idea.KotlinFileType;
import org.jetbrains.kotlin.psi.KtFile;

import java.io.File;
import java.io.IOException;

/**
* Parses Kotlin source file and returns AST representing the source code.
*/
public class KotlinParser {
    private String source;
    private File sourceFile;
    private KotlinCoreEnvironment environment;

    public KotlinParser(File sourceFile, KotlinCoreEnvironment environment) throws IOException {
        this.sourceFile = sourceFile;
        this.environment = environment;

        // Kotlin compiler will throw an exception if input file has DOS or Mac line separator,
        // when accessing internal "Document" entity (e.g. PsiFile.getViewProvider().getDocument()).
        // The error is thrown at com.intellij.openapi.editor.impl.DocumentImpl.assertValidSeparators().
        // To work around that, convert all "\r\n" and "\r" to "\n" manually.
        this.source = new String(FileUtils.readFileToCharArray(sourceFile))
                .replaceAll("\r\n", "\n").replaceAll("\r", "\n");
    }

    public KtFile parse() throws KotlinParserException {
        Project project = environment.getProject();
        PsiManager manager = PsiManager.getInstance(project);

        LightVirtualFile virtualFile = new LightVirtualFile(sourceFile.getName(), KotlinFileType.INSTANCE, source);
        KtFile ktFile = (KtFile) manager.findFile(virtualFile);
        if (ktFile == null) throw new KotlinParserException(sourceFile.getPath() + ": Unknown Kotlin parsing error.");

        return ktFile;
    }
}
