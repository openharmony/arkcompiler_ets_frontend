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

import static com.ohos.migrator.apimapper.Util.*;
import static com.ohos.migrator.staticTS.parser.StaticTSParser.CallExpressionContext;
import static com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;
import static com.ohos.migrator.staticTS.parser.StaticTSParser.MemberAccessExpressionContext;
import static com.ohos.migrator.staticTS.parser.StaticTSParser.IdentifierExpressionContext;
import static com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentContext;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

// | singleExpression typeArguments? arguments                              # CallExpression
//  <CallExpression name="name.of.the.function.to.call">
//      <TypeArgjments/> <!-- Optional -->
//      <Arguments/> <!-- Optional -->
//  </CallExpression>
public class CallExpression {
    static public String tag = "CallExpression";

    private String arktsMethodName = null;
    private TypeReference typeReference = null; // Optional. Type of the class/interface for static methods.
    private TypeArguments typeArguments = null;
    private Arguments arguments = null;

    static public CallExpression read(XMLEventReader xmlReader, XMLEvent xmlCallExpressionEvent) throws XMLStreamException {
        CallExpression callExpression = new CallExpression();

        StartElement callExpressionElement = xmlCallExpressionEvent.asStartElement();
        callExpression.arktsMethodName = getAttribute(callExpressionElement, arktsMethodNameAttr);

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (TypeReference.tag.equals(tag)) {
                    callExpression.typeReference = TypeReference.read(xmlReader, xmlEvent);
                }
                else if (TypeArguments.tag.equals(tag)) {
                    callExpression.typeArguments = TypeArguments.read(xmlReader);
                }
                else if (Arguments.tag.equals(tag)) {
                    callExpression.arguments = Arguments.read(xmlReader, xmlEvent);
                }
                else assert false;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (CallExpression.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (TypeArguments.tag.equals(tag) || Arguments.tag.equals(tag));
                }
            }
        }

        return callExpression;
    }

    public SingleExpressionContext buildArktsNode(SingleExpressionContext arktsOrigObject, List<TypeArgumentContext> arktsOrigTypeArguments, List<SingleExpressionContext> arktsOrigArguments) {
        SingleExpressionContext arktsCallExpressionParent = new SingleExpressionContext();
        CallExpressionContext arktsCallExpression = new CallExpressionContext(arktsCallExpressionParent);
        arktsCallExpression.setParent(arktsCallExpressionParent);

        String arktsTypeName = (typeReference != null) ? typeReference.getArktsName() : null;

        if (arktsTypeName != null) {
            // | singleExpression Dot identifier  # MemberAccessExpression
            SingleExpressionContext arktsSingleExpression = new SingleExpressionContext();
            MemberAccessExpressionContext arktsMemberAccessExpression = new MemberAccessExpressionContext(arktsSingleExpression);
            arktsMemberAccessExpression.setParent(arktsSingleExpression);
            arktsCallExpression.addChild(arktsSingleExpression).setParent(arktsCallExpression);

            arktsMemberAccessExpression.addChild(NodeBuilder.typeReference(arktsTypeName)).setParent(arktsMemberAccessExpression);

            arktsMemberAccessExpression.addChild(NodeBuilder.terminalIdentifier(arktsMethodName));
        }
        else {
            SingleExpressionContext arktsSingleExpression = new SingleExpressionContext();
            IdentifierExpressionContext arktsIdentifierExpression = new IdentifierExpressionContext(arktsSingleExpression);
            arktsCallExpression.addChild(arktsIdentifierExpression).setParent(arktsCallExpression);
            arktsIdentifierExpression.setParent(arktsSingleExpression);
            arktsIdentifierExpression.addChild(NodeBuilder.terminalIdentifier(arktsMethodName));
        }

        if (typeArguments != null) {
            arktsCallExpression.addChild(typeArguments.buildArktsNode(arktsOrigTypeArguments)).setParent(arktsCallExpression);
        }

        if (arguments != null) {
            arktsCallExpression.addChild(arguments.buildArktsNode(arktsOrigObject, arktsOrigTypeArguments, arktsOrigArguments)).setParent(arktsCallExpression);
        }

        return arktsCallExpressionParent;
    }
}
