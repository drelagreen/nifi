import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dom.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class Checker {
    public static void main(String[] args) throws ParserConfigurationException, SAXException, IOException {
        Document document = Util.buildDocument(new File("E://work/signer2.1/src/main/resources/xml.xml"));
        document.normalize();
        Util.trimWhitespace(document.getDocumentElement());
        Checker checker = new Checker();
        try {
            System.out.println(checker.check(document));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("\nfalse");
        }
    }

    boolean check(Document document) throws Exception {
        NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nodeList.getLength()==0){
            throw new Exception("Cannot find Signature");
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

        public Key getKey() { return pk; }
    }
}

