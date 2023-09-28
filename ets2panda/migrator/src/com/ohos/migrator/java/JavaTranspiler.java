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

package com.ohos.migrator.java;

import com.ohos.migrator.AbstractTranspiler;

import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.TranspileException;

import com.ohos.migrator.staticTS.parser.StaticTSParser.*;

import org.eclipse.jdt.core.dom.ASTNode;
import org.eclipse.jdt.core.dom.CompilationUnit;

import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

/**
 * Java to StaticTS transpiler class inherited from AbstractTranspiler class.
 * Transpilation consists of 3 steps:
 * 1) Parse Java source file and create Java AST.
 * 2) Translate Java AST to StaticTS AST.
 * 3) Write output file with StaticTS source code.
*/

public class JavaTranspiler extends AbstractTranspiler {

    private boolean noxrefs = false;
    private JavaParser javaParser;
    public JavaTranspiler(List<File> src, List<File> libs, String outDir, boolean noxrefs) {
       super(src, libs, outDir);
       this.noxrefs = noxrefs;
    }

    @Override
    public void transpileFile(File srcFile) throws TranspileException {
        try {
            CompilationUnit javaCU = parse(srcFile);

            CompilationUnitContext stsCU = transform(javaCU, srcFile);

            migrateAPI(stsCU);

            write(stsCU, srcFile);
        } catch (IOException e) {
            throw new TranspileException(ResultCode.InputError, e);
        } catch (JavaParserException e) {
            StringBuilder sb = new StringBuilder("Failed to parse ");
            sb.append(srcFile.getPath()).append(" due to ");
            if (e.getCause() != null) {
                sb.append(e.getCause().toString());
            }
            else
                sb.append(e.getMessage());

            throw new TranspileException(ResultCode.ParseError, sb.toString());
        }
    }

    private CompilationUnit parse(File srcFile) throws IOException, JavaParserException {
        javaParser = new JavaParser(srcFile, sourceFiles, libFiles, noxrefs);
        return javaParser.parse();
    }

    private CompilationUnitContext transform(CompilationUnit javaCU, File srcFile) {
        char[] javaSource = javaParser.getJavaSource();
        JavaTransformer transformer = new JavaTransformer(javaCU, javaSource, srcFile);
        return transformer.transform();
    }

    @Override
    public double getConversionRate() {
        return JavaTransformer.getTransformationRate() * 100.;
    }

    private String exceptionMessage(Exception e) {
        String msg = e.getMessage();
        if (msg == null) {
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            assert stackTraceElements != null;
            int n = Math.min(10, stackTraceElements.length); // Don't write to long stack trace.

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < n; i++) {
                StackTraceElement ste = stackTraceElements[i];
                sb.append(ste.toString()).append("\n");
            }

            msg = sb.toString();
        }

        return msg;
    }

    @Override
    public void migrateAPI(CompilationUnitContext arktsCU)
    {
        try {
            File path = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
            if (path.getName().toLowerCase().endsWith(".jar")) {
                path = path.getParentFile();
            }

            File configDir = new File(path, "config");
            File f = new File(configDir, "java-api-mapper.xml");
            String rulesFilePath = f.getPath();
            JavaApiMapper mapper = JavaApiMapper.readRules(rulesFilePath);
            mapper.visitCompilationUnit(arktsCU);
        }
        catch (FileNotFoundException | URISyntaxException e) {
            Main.addError(ResultCode.InputError, "Fail to find the API mapper rules file. \n" + exceptionMessage(e));
        }
        catch (XMLStreamException e) {
            Main.addError(ResultCode.InputError, "Fail to parse the API mapper rules file. \n" + exceptionMessage(e));
        }
    }
}
