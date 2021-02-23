package ru.greenatom.processors.nifixmlchecker;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

public class Util {
    public static void sendDocument(Document document, OutputStream outputStream) throws TransformerException, FileNotFoundException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        transformer.transform(new DOMSource(document), new StreamResult(outputStream));
    }

    public static Document buildDocument(byte[] bytes) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilder db = getDocumentBuilder();
        return db.parse(new ByteArrayInputStream(bytes));
    }

    public static Document buildDocument(File file) throws IOException, SAXException, ParserConfigurationException {
        DocumentBuilder db = getDocumentBuilder();
        return db.parse(file);
    }

    public static Document buildDocument(InputStream inputStream) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilder db = getDocumentBuilder();
        return db.parse(inputStream);
    }

    public static DocumentBuilder getDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder();
    }

    public static void trimWhitespace(Node node)
    {
        NodeList children = node.getChildNodes();
        for(int i = 0; i < children.getLength(); ++i) {
            Node child = children.item(i);
            if(child.getNodeType() == Node.TEXT_NODE) {
                child.setTextContent(child.getTextContent().trim());
            }
            trimWhitespace(child);
        }
    }
}
