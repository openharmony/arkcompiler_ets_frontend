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

package com.ohos.migrator.visualizer;

import com.ohos.migrator.staticTS.parser.StaticTSLexer;
import com.ohos.migrator.staticTS.parser.StaticTSParser;

import org.antlr.v4.gui.TreeViewer;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;

import java.io.IOException;
import java.util.Arrays;

public class Main {
  public static void main(String[] args) {

    if (args.length > 0) {
      try {
        CharStream input = CharStreams.fromFileName(args[0]);
        StaticTSLexer lexer = new StaticTSLexer(input);
        CommonTokenStream tokens = new CommonTokenStream(lexer);
        StaticTSParser parser = new StaticTSParser(tokens);

        ParseTree tree = parser.compilationUnit();

        TreeViewer viewr = new TreeViewer(Arrays.asList(parser.getRuleNames()), tree);
        viewr.open();
      } catch (IOException e) {
        System.out.println("Something went wrong: " + e);
      }
    } else {
      System.out.println("Please provide *.sts file to show its parse tree.");
    }
  }
}