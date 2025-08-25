package be.egelke.ehealth.server.mock;

import lombok.extern.slf4j.Slf4j;
import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.sts.claims.ClaimsParser;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;

@Slf4j
public class AuthClaimsParser implements ClaimsParser {

    public static final String AUTH_CLAIMS_DIALECT =
            "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";
    @Override
    public Claim parse(Element claim) {
        String claimLocalName = claim.getLocalName();
        //String claimNS = claim.getNamespaceURI();

        if ("ClaimType".equals(claimLocalName) || "ClaimValue".equals(claimLocalName)) {
            String claimTypeUri = claim.getAttributeNS(null, "Uri");
            String claimTypeOptional = claim.getAttributeNS(null, "Optional");
            Claim requestClaim = new Claim();
            try {
                requestClaim.setClaimType(new URI(claimTypeUri));
            } catch (URISyntaxException e) {
                log.warn("Cannot create URI from the given ClaimType attribute value {}", claimTypeUri, e);
            }
            requestClaim.setOptional(Boolean.parseBoolean(claimTypeOptional));

            if ("ClaimValue".equals(claimLocalName)) {
                Node valueNode = claim.getFirstChild();
                if (valueNode != null) {
                    if ("Value".equals(valueNode.getLocalName())) {
                        requestClaim.addValue(valueNode.getTextContent().trim());
                    } else {
                        log.warn("Unsupported child element of ClaimValue element {}", valueNode.getLocalName());
                        return null;
                    }
                } else {
                    log.warn("No child element of ClaimValue element available");
                    return null;
                }
            }

            return requestClaim;
        }

        log.warn("Found unknown element: {}", claimLocalName );
        return null;
    }

    @Override
    public String getSupportedDialect() {
        return AUTH_CLAIMS_DIALECT;
    }
}
