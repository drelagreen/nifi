import org.w3c.dom.Document;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

public class Signer {
    public static void main(String[] args) throws Exception {
        Signer signer = new Signer();
        File file = new File("E://work/signer2.1/src/main/resources/xml.xml");
        Document document = Util.buildDocument(file);
        document.normalize();
        Util.trimWhitespace(document.getDocumentElement());
        signer.sign(document);
        Util.saveDocument(document, file);
    }

    void sign(Document document) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), document.getDocumentElement());

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        Reference reference = factory.newReference
                ("", factory.newDigestMethod(DigestMethod.SHA256, null),
                        Collections.singletonList(
                                factory.newTransform(
                                        Transform.ENVELOPED, (XMLStructure) null)),
                        null, null);

        SignedInfo signedInfo = factory.newSignedInfo(
                factory.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                        (C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.DSA_SHA256, null),
                Collections.singletonList(reference)
        );

        KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();

        KeyValue keyValue = keyInfoFactory.newKeyValue(kp.getPublic());
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue));

        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);

        signature.sign(dsc);
    }

}
