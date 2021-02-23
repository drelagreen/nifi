/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ru.greenatom.processors.nifixmlchecker;

import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.io.StreamCallback;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;


@Tags({"XML", "Checker", "Validator", "file", "document", "version2"})
@CapabilityDescription("XML signature verification")
@InputRequirement(InputRequirement.Requirement.INPUT_REQUIRED)
public class MyProcessor extends AbstractProcessor {

    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("XML has a valid signature")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("XML does not have a valid signature")
            .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;


    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        AtomicReference<Boolean> errors = new AtomicReference<>();
        errors.set(Boolean.TRUE);

        flowFile = session.write(flowFile, new StreamCallback() {
            @Override
            public void process(InputStream inputStream, OutputStream outputStream) throws IOException {
                try {
                    boolean res;
                    Document document = Util.buildDocument(inputStream);
                    document.normalize();
                    Util.trimWhitespace(document.getDocumentElement());
                    try {
                        res = check(document);
                    } catch (Exception e) {
                        getLogger().error("EXCEPTION_0");

                        getLogger().error(e.getLocalizedMessage());
                        res = false;
                    }
                    if (res) {
                        Util.sendDocument(document,outputStream);
                        errors.set(Boolean.FALSE);
                    }
                } catch (Exception e) {
                    getLogger().error(e.getLocalizedMessage());
                    getLogger().error("EXCEPTION_1");

                    throw new IOException("Cannot validate xml");
                }
            }
        });

        if (errors.get()) {
            session.transfer(flowFile, REL_FAILURE);
        } else {
            session.transfer(flowFile, REL_SUCCESS);
        }

    }

    private boolean check(Document document) throws XMLSignatureException, MarshalException {
        NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nodeList.getLength() == 0) {
            throw new XMLSignatureException("Cannot find Signature");
        }

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

        DOMValidateContext validateContext = new DOMValidateContext(new KeyValueKeySelector(), nodeList.item(0));

        XMLSignature signature = factory.unmarshalXMLSignature(validateContext);

        return signature.validate(validateContext);
    }

    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            for (Object o : list) {
                XMLStructure xmlStructure = (XMLStructure) o;
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue) xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        static boolean algEquals(String algURI, String algName) {
            return algName.equalsIgnoreCase("DSA") &&
                    algURI.equalsIgnoreCase("http://www.w3.org/2009/xmldsig11#dsa-sha256");
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;

        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() {
            return pk;
        }
    }
}