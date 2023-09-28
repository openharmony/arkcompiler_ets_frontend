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

import com.ohos.migrator.staticTS.NodeBuilderBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.SingleExpressionContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.NewClassInstanceExpressionContext;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import java.util.List;

public class NewClassInstanceExpression {
    static public String tag = "NewClassInstanceExpression";
    private TypeReference typeReference = null;
    private Arguments arguments = null;

    static public NewClassInstanceExpression read(XMLEventReader xmlReader) throws XMLStreamException {
        NewClassInstanceExpression newClassExpression = new NewClassInstanceExpression();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (TypeReference.tag.equals(tag)) {
                    newClassExpression.typeReference = TypeReference.read(xmlReader, xmlEvent);
                }
                else if (Arguments.tag.equals(tag)) {
                    newClassExpression.arguments = Arguments.read(xmlReader, xmlEvent);
                }
                else assert false : "Unexpected XmlElement " + tag;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                assert NewClassInstanceExpression.tag.equals(endElement.getName().getLocalPart());
                break;
            }
        }

        return newClassExpression;
    }

    // ArkTS:
    //    New typeArguments? typeReference arguments? classBody?  # NewClassInstanceExpression
    public SingleExpressionContext buildArktsNode(SingleExpressionContext arktsOrigObject, List<SingleExpressionContext> arktsOrigArguments) {
        NewClassInstanceExpressionContext arktsNewClassInstanceExpression = new NewClassInstanceExpressionContext(new SingleExpressionContext());
        arktsNewClassInstanceExpression.addChild(NodeBuilderBase.terminalNode(StaticTSParser.New));

        if (typeReference != null) {
            arktsNewClassInstanceExpression.addChild(typeReference.buildArktsNode(null)).setParent(arktsNewClassInstanceExpression); // There are no original type arguments in this case.
        }

        if (arguments != null) {
            arktsNewClassInstanceExpression.addChild(arguments.buildArktsNode(arktsOrigObject, null, arktsOrigArguments)).setParent(arktsNewClassInstanceExpression);
        }

        return arktsNewClassInstanceExpression;
    }
}
