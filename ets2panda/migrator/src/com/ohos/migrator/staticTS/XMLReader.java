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

import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.staticTS.parser.DummyContext;
import com.ohos.migrator.staticTS.parser.StaticTSContextBase;
import com.ohos.migrator.staticTS.parser.StaticTSParser;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;
import org.antlr.v4.runtime.tree.TerminalNode;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Constructor;
import java.util.Stack;

public class XMLReader {
    private File xmlFile;
    private Stack<StaticTSContextBase> nodeStack = new Stack<>();

    private static final QName terminalKindAttr = new QName("kind");
    private static final QName terminalTextAttr = new QName("text");
    private static final QName terminalIsLeadingCommentAttr = new QName("isLeadingComment");
    private static final QName parentFieldAttr = new QName("parentField");

    private static final String classNamePrefix = StaticTSParser.class.getName();
    private static final String terminalNodeName = "TerminalNode";

    public XMLReader(File xmlFile) {
        this.xmlFile = xmlFile;
    }

    public CompilationUnitContext read() throws XMLStreamException, IOException {
        FileInputStream fis = new FileInputStream(xmlFile);
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        XMLEventReader xmlReader = xmlInputFactory.createXMLEventReader(fis);

        CompilationUnitContext result = null;
        try {
            while (xmlReader.hasNext()) {
                XMLEvent event = xmlReader.nextEvent();

                try {
                    StaticTSContextBase lastNode = nodeStack.empty() ? null : nodeStack.peek();

                    if (event.isStartElement()) {
                        StartElement startElement = event.asStartElement();
                        String tagName = startElement.getName().getLocalPart();

                        if (terminalNodeName.equals(tagName)) {
                            // Create the terminal and add it to the last node in the stack.
                            // Ignore if node stack is empty or terminal is invalid.
                            if (lastNode != null) {
                                TerminalNode terminal = createTerminal(startElement);
                                if (terminal != null) {
                                    String isLeadingComment = getXMLAttributeValue(startElement, terminalIsLeadingCommentAttr);
                                    if (isLeadingComment != null && !isLeadingComment.isEmpty()) {
                                        if (Boolean.parseBoolean(isLeadingComment))
                                            lastNode.addLeadingComment(terminal);
                                        else
                                            lastNode.addTrailingComment(terminal);
                                    }
                                    else {
                                        lastNode.addChild(terminal);
                                    }
                                }
                                else
                                    reportError("Invalid XML tag emitted by TS transpiler", startElement);
                            }

                            continue;
                        }

                        // These two calls work as a filter. If current tag  doesn't correspond to
                        // an AST node, they will throw, and the tag will be ignored as the result.
                        String namePrefix = classNamePrefix + "$";
                        if (DummyContext.class.getSimpleName().equals(tagName)) {
                            // DummyContext is the only AST node class not defined inside StaticTSParser.
                            // Fix namePrefix to allow it to load correctly.
                            int pos = namePrefix.lastIndexOf('.');
                            if (pos > 0) namePrefix = namePrefix.substring(0, pos+1);
                        }
                        Class tagClass = Class.forName(namePrefix + tagName);
                        Class<? extends StaticTSContextBase> nodeClass =
                                tagClass.asSubclass(StaticTSContextBase.class);

                        // Create node object and push it onto node stack.
                        // Also add it to AST if it exists (i.e., lastNode not null).
                        StaticTSContextBase node = createNode(nodeClass, lastNode);

                        if (node != null) {
                            if (lastNode != null) {
                                lastNode.addChild(node).setParent(lastNode);

                                // For a labeled child node, set the corresponding field
                                // of its parent node.
                                String parentField = getXMLAttributeValue(startElement, parentFieldAttr);
                                if (parentField != null && !parentField.isEmpty()) {
                                    setParentField(lastNode, node, parentField, startElement);
                                }
                            }

                            nodeStack.push(node);
                        }
                        else
                            reportError("Failed to create AST node for XML tag emitted by TS transpiler", startElement);
                    }
                    else if (event.isEndElement()) {
                        EndElement endElement = event.asEndElement();
                        String tagName = endElement.getName().getLocalPart();

                        // Terminals are never added into nodeStack
                        // (see above) so just ignore them here.
                        if (terminalNodeName.equals(tagName)) continue;

                        // Check that node stack is not empty and closing tag name matches
                        // type of the last node in stack before popping it off. The latter
                        // test takes care of the tags we skipped above due  to exceptions.
                        if (lastNode != null && lastNode.getClass().getSimpleName().equals(tagName)) {
                            StaticTSContextBase node = nodeStack.pop();

                            // Bail out when we see closing tag for CompilationUnitContext.
                            if (node.getRuleIndex() == StaticTSParser.RULE_compilationUnit) {
                                result = (CompilationUnitContext) node;
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    // Report error and swallow exception to ignore the tag and continue iterating
                    reportError("Ignoring unexpected XML tag emitted by TS transpiler", event);
                }
            }
        }
        finally {
            // Close resources, most importantly  the FileInputStream
            // object,  to allow further manipulations with XML file,
            // e.g., deleting it (see TSTranspiler.transpileFile method)
            fis.close();
            xmlReader.close();
        }

        return result;
    }

    private TerminalNode createTerminal(StartElement startElement) {
        // Sanity check.
        if (!terminalNodeName.equals(startElement.getName().getLocalPart()))
            return null;

        String kind = getXMLAttributeValue(startElement, terminalKindAttr);
        if (kind == null || kind.isEmpty()) return null;

        for (int i = 1; i < StaticTSParser.VOCABULARY.getMaxTokenType(); ++i) {
            if (kind.equals(StaticTSParser.VOCABULARY.getSymbolicName(i))) {
                String text = getXMLAttributeValue(startElement, terminalTextAttr);
                if (text != null && !text.isEmpty()) {
                    return NodeBuilderBase.terminalNode(i, text);
                }

                return NodeBuilderBase.terminalNode(i);
            }
        }

        return null;
    }

    // NOTE: We don't care about specific exception types this function
    // can throw as we catch and process them all the same way.
    private StaticTSContextBase createNode(Class<? extends StaticTSContextBase> nodeClass,
                                           StaticTSContextBase parent) throws Exception {
        // Pick up node ctor with one or two parameters.
        // AntLR guarantees that all rule-based node classes
        // have at least ctor that satisfies this condition.
        Constructor nodeCtor = null;
        for (Constructor ctor : nodeClass.getConstructors()) {
            int numParams = ctor.getParameterCount();
            if (numParams > 0 && numParams < 3) {
                nodeCtor = ctor;
                break;
            }
        }

        // This check should never be true!
        if (nodeCtor == null) return null;

        // Construct arguments array and invoke selected ctor.
        Object[] ctorArgs = nodeCtor.getParameterCount() > 1 ?
                new Object[] { parent, 0 } :
                new Object[] { parent };

        return (StaticTSContextBase)nodeCtor.newInstance(ctorArgs);
    }

    private String getXMLAttributeValue(StartElement startElement, QName attrName) {
        Attribute attr = startElement.getAttributeByName(attrName);
        if (attr != null) {
            String attrVal = attr.getValue();
            if (attrVal != null && !attrVal.isEmpty())
                return attrVal;
        }

        return null;
    }

    private void reportError(String message, XMLEvent xmlEvent) {
        Main.addError(ResultCode.TranspileError, message + " at " +
                      xmlFile.getPath() + ":" + xmlEvent.getLocation().getLineNumber());
    }

    private void setParentField(StaticTSContextBase parent, StaticTSContextBase child, String parentField, StartElement startElement) throws Exception {
        Class<? extends StaticTSContextBase> parentNodeClass = parent.getClass();
        for (Field field : parentNodeClass.getFields()) {
            if (field.getName().equals(parentField)) {
                field.set(parent, child);
                return;
            }
        }

        reportError("Failed to set field of parent node \"" + parentField +  "\" because of field name mismatch", startElement);
    }
}
