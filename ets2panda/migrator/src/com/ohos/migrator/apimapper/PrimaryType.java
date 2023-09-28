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
import com.ohos.migrator.staticTS.parser.StaticTSParser.PrimaryTypeContext;

import static com .ohos.migrator.apimapper.Util.*;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

// primaryType: predefinedType | typeReference | arrayType;

public class PrimaryType {
    static public String tag = "PrimaryType";

    private String predefinedType = null;
    private TypeReference typeReference = null;
    private ArrayType arrayType = null;

    static PrimaryType read(XMLEventReader xmlReader) throws XMLStreamException {
        PrimaryType primaryType = new PrimaryType();

        while (xmlReader.hasNext()) {
            XMLEvent xmlEvent = xmlReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                String tag = startElement.getName().getLocalPart();

                if (tagPredefinedType.equals(tag)) {
                    primaryType.predefinedType = getAttribute(startElement, nameAttr);
                }
                else if (TypeReference.tag.equals(tag)) {
                    primaryType.typeReference = TypeReference.read(xmlReader, xmlEvent);
                }
                else if (ArrayType.tag.equals(tag)) {
                    primaryType.arrayType = ArrayType.read(xmlReader);
                }
                else assert false;
            }
            else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                String tag = endElement.getName().getLocalPart();

                if (PrimaryType.tag.equals(tag)) {
                    break;
                }
                else {
                    assert (tagPredefinedType.equals(tag) || TypeReference.tag.equals(tag) || ArrayType.tag.equals(tag));
                }
            }
        }

        return primaryType;
    }

    public PrimaryTypeContext buildArktsNode() {
        PrimaryTypeContext arktsPrimaryType = new PrimaryTypeContext(null, 0);

        if (!isStringEmpty(predefinedType)) {
            arktsPrimaryType.addChild(NodeBuilder.predefinedType(predefinedType)).setParent(arktsPrimaryType);
        }
        else if (typeReference != null) {
            arktsPrimaryType.addChild(typeReference.buildArktsNode(null)).setParent(arktsPrimaryType);
        }
        else {
            assert (arrayType != null);
            arktsPrimaryType.addChild(arrayType.buildArktsNode(null)).setParent(arktsPrimaryType);
        }

        return arktsPrimaryType;
    }
}
