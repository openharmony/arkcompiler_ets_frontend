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
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeReferenceContext;
import com.ohos.migrator.staticTS.parser.StaticTSParser.TypeArgumentContext;
import static com.ohos.migrator.apimapper.Util.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.List;

//  <TypeReference arktsTypeName="arktsNname">
//      <TypeArguments>         // Optional type arguments. Any sequence of children of following types:
//          <TpeReference/>
//          <ArrayType/>        // Look ArrayType class for details.
//          <WildcardType/>     // Look WildcardType class for details.
//      </TypeArguments>
//</TypeReference>
public class TypeReference {
    static public String tag = "TypeReference";
    private String arktsTypeName = null;
    private TypeArguments typeArguments = null;

    public String getArktsName() {
        return arktsTypeName;
    }

    static public TypeReference read(XMLEventReader xmlReader, XMLEvent xmlTypeReferenceEvent) throws XMLStreamException {
        TypeReference typeReference = new TypeReference();

        assert xmlTypeReferenceEvent.isStartElement();
        StartElement startElement = xmlTypeReferenceEvent.asStartElement();
        typeReference.arktsTypeName = getAttribute(startElement, arktsTypeNameAttr);

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (TypeArguments.tag.equals(tag)) {
                    typeReference.typeArguments = TypeArguments.read(xmlReader);
                }
                else
                    assert false : "<TypeReference> may has as a child only <TypeArguments>.";
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (TypeReference.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (TypeArguments.tag.equals(tag));
                }
            }
        }

        return typeReference;
    }

    public TypeReferenceContext buildArktsNode(List<TypeArgumentContext> arktsOrigTypeArguments) {
        TypeReferenceContext arktsTypeReference = NodeBuilder.typeReference(arktsTypeName);

        if (typeArguments != null) {
            arktsTypeReference.addChild(typeArguments.buildArktsNode(arktsOrigTypeArguments)).setParent(arktsTypeReference);
        }

        return arktsTypeReference;
    }
}
