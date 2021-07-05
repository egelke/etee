package be.egelke.ehealth.server.mock;

import lombok.Getter;
import org.apache.cxf.ws.security.wss4j.CryptoCoverageUtil;
import org.apache.cxf.ws.security.wss4j.DefaultCryptoCoverageChecker;

public class ExtCryptoCoverageChecker extends DefaultCryptoCoverageChecker {

    @Getter
    private boolean signBST;

    public ExtCryptoCoverageChecker() {
        setSignBST(true);
    }

    public final void setSignBST(boolean signBST) {
        this.signBST = signBST;

        XPathExpression soap11Expression =
                new XPathExpression(
                        "/soapenv:Envelope/soapenv:Header/wsse:Security/wsse:BinarySecurityToken",
                        CryptoCoverageUtil.CoverageType.SIGNED
                );
        XPathExpression soap12Expression =
                new XPathExpression(
                        "/soapenv12:Envelope/soapenv12:Header/wsse:Security/wsse:BinarySecurityToken",
                        CryptoCoverageUtil.CoverageType.SIGNED
                );

        if (signBST) {
            if (!xPaths.contains(soap11Expression)) {
                xPaths.add(soap11Expression);
            }
            if (!xPaths.contains(soap12Expression)) {
                xPaths.add(soap12Expression);
            }
        } else {
            if (xPaths.contains(soap11Expression)) {
                xPaths.remove(soap11Expression);
            }
            if (xPaths.contains(soap12Expression)) {
                xPaths.remove(soap12Expression);
            }
        }
    }
}
