import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


class VIniFiler {

	private String IniFile = "";
	
	public String IniReadValue(String sPart, String sParam, String sDefault) {
		String sResult = sDefault;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder;
        Document doc = null;
        try {
            builder = factory.newDocumentBuilder();
            doc = builder.parse(IniFile);

            XPathFactory xpathFactory = XPathFactory.newInstance();
            XPath xpath = xpathFactory.newXPath();
            XPathExpression expr = xpath.compile("//"+sPart+"/"+sParam);
            NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

            for (int i = 0; i < nodes.getLength(); i++)
				sResult = nodes.item(i).getTextContent();
			
        } catch (ParserConfigurationException | SAXException | IOException e) {
            e.printStackTrace();
			return sDefault;
        } catch (XPathExpressionException e) {
            e.printStackTrace();
			return sDefault;
        }
		return sResult;
	}

	VIniFiler(String sIniFile) {
		this.IniFile = sIniFile;
	}
}