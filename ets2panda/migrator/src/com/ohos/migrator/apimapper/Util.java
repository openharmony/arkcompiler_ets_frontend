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

package com.ohos.migrator.apimapper;

import com.ohos.migrator.java.NodeBuilder;
import com.ohos.migrator.staticTS.parser.StaticTSParser.MemberAccessExpressionContext;

import javax.xml.namespace.QName;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;

public class Util {
    static public QName indexAttr = new QName("index");
    static public QName nameAttr = new QName("name");
    static public QName valueAttr = new QName("value");
    static public QName operationAttr = new QName("operation");
    static public QName typeAttr = new QName("type");
    static public QName arktsMethodNameAttr = new QName("arktsMethodName");
    static public QName arktsNameAttr = new QName("arktsName");
    static public QName arktsTypeNameAttr = new QName("arktsTypeName");
    static public QName arktsItemAttr = new QName("arktsItem");
    static public QName arktsAliasAttr = new QName("arktsAlias");
    static public QName arktsFromAttr = new QName("arktsFrom");
    static public String tagSrcArgument = "SrcArgument";
    static public String tagSrcArgumentsTail = "SrcArgumentsTail";
    static public String tagSrcTypeArgument = "SrcTypeArgument";
    static public String tagPredefinedType = "PredefinedType";

    static public boolean isStringEmpty(String s) {
        return (s == null || s.isEmpty());
    }

    // | singleExpression Dot Identifier  #MemberAccessExpression
    static public void rebuildMemberAccessExpression(MemberAccessExpressionContext arktsMemberAccessExpr, String arktsNewType, String arktsNewName, TypeArguments newTypeArguments) {
        if (!isStringEmpty(arktsNewName)) {
            int i = arktsMemberAccessExpr.children.indexOf(arktsMemberAccessExpr.Identifier());
            arktsMemberAccessExpr.children.remove(i);
            arktsMemberAccessExpr.children.add(i, NodeBuilder.terminalIdentifier(arktsNewName));
        }

        if (!isStringEmpty(arktsNewType)) {
            // TODO:
        }

        if (newTypeArguments != null) {
            // TODO:
        }
    }

    static public String getAttribute(StartElement element, QName attrName) {
        Attribute attribute = element.getAttributeByName(attrName);
        return attribute != null ? attribute.getValue() : null;
    }
}
