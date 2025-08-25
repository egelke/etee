package be.egelke.ehealth.server.mock;

import lombok.SneakyThrows;
import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBus;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.claims.IdentityClaimsParser;
import org.apache.cxf.sts.provider.DefaultSecurityTokenServiceProvider;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.ws.addressing.WSAddressingFeature;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.apache.cxf.ws.security.tokenstore.MemoryTokenStore;
import org.apache.cxf.ws.security.tokenstore.TokenStore;
import org.apache.cxf.ws.security.wss4j.DefaultCryptoCoverageChecker;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.CryptoBase;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import test.EchoPort;
import test.EchoService;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.ws.Endpoint;
import javax.xml.ws.soap.SOAPBinding;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;

@Configuration
public class WebServiceConfig {


    @Bean(name=Bus.DEFAULT_BUS_ID)
    public SpringBus springbus() {
        LoggingFeature lf = new LoggingFeature();
        lf.setPrettyLogging(true);

        SpringBus cxfbus = new  SpringBus();
        cxfbus.getFeatures().add(lf);
        return cxfbus;
    }


    @Bean
    public Endpoint soap11Plain(Bus bus, EchoPort service) {
        EndpointImpl endpoint = new EndpointImpl(bus, service);
        endpoint.setBindingUri(SOAPBinding.SOAP11HTTP_BINDING);
        endpoint.publish("/echo/soap11");
        return endpoint;
    }

    @Bean
    public Endpoint soap12Plain(Bus bus, EchoPort service) {
        EndpointImpl endpoint = new EndpointImpl(bus, service);
        endpoint.setBindingUri(SOAPBinding.SOAP12HTTP_BINDING);
        endpoint.getFeatures().add(new WSAddressingFeature());
        endpoint.publish("/echo/soap12");
        return endpoint;
    }

    @Bean
    public Endpoint soap11Wss10(Bus bus, EchoPort service) {
        EndpointImpl endpoint = new EndpointImpl(bus, service);
        endpoint.setBindingUri(SOAPBinding.SOAP11HTTP_BINDING);

        Map<String, Object> inProps = new HashMap<>();
        inProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE );

        inProps.put(WSHandlerConstants.SIG_PROP_REF_ID, "signatureProperties");
        Properties sigProps = new Properties();
        sigProps.put("org.apache.wss4j.crypto.provider", "be.egelke.ehealth.server.mock.AllowAllCrypto");

        inProps.put("signatureProperties", sigProps);
        endpoint.getInInterceptors().add(new WSS4JInInterceptor(inProps));
        DefaultCryptoCoverageChecker signOnlyTs = new DefaultCryptoCoverageChecker();
        signOnlyTs.setSignTimestamp(true);
        signOnlyTs.setSignBody(false);
        signOnlyTs.setEncryptBody(false);
        signOnlyTs.setSignAddressingHeaders(false);
        signOnlyTs.setSignUsernameToken(false);
        signOnlyTs.setEncryptUsernameToken(false);
        endpoint.getInInterceptors().add(signOnlyTs);
        endpoint.publish("/echo/soap11wss10");
        return endpoint;
    }

    @Bean
    public Endpoint soap11Wss10SignAll(Bus bus, EchoPort service) {
        EndpointImpl endpoint = new EndpointImpl(bus, service);
        endpoint.setBindingUri(SOAPBinding.SOAP11HTTP_BINDING);

        Map<String, Object> inProps = new HashMap<>();
        inProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE );
        inProps.put(WSHandlerConstants.SIG_PROP_REF_ID, "signatureProperties");
        Properties sigProps = new Properties();
        sigProps.put("org.apache.wss4j.crypto.provider", "be.egelke.ehealth.server.mock.AllowAllCrypto");
        inProps.put("signatureProperties", sigProps);
        endpoint.getInInterceptors().add(new WSS4JInInterceptor(inProps));
        endpoint.getInInterceptors().add(new ExtCryptoCoverageChecker());
        endpoint.publish("/echo/soap11wss10all");
        return endpoint;
    }

    @Bean
    public Endpoint soap12Wss10(Bus bus, EchoPort service) {
        EndpointImpl endpoint = new EndpointImpl(bus, service);
        endpoint.setBindingUri(SOAPBinding.SOAP12HTTP_BINDING);

        Map<String, Object> inProps = new HashMap<>();
        inProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE );
        inProps.put(WSHandlerConstants.SIG_PROP_REF_ID, "signatureProperties");
        Properties sigProps = new Properties();
        sigProps.put("org.apache.wss4j.crypto.provider", "be.egelke.ehealth.server.mock.AllowAllCrypto");
        inProps.put("signatureProperties", sigProps);

        Map<String, Object> outProps = new HashMap<>();
        outProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP);

        endpoint.getInInterceptors().add(new WSS4JInInterceptor(inProps));
        endpoint.getOutInterceptors().add(new WSS4JOutInterceptor(outProps));
        endpoint.getFeatures().add(new WSAddressingFeature());
        endpoint.publish("/echo/soap12wss10");
        return endpoint;
    }

    @Bean
    public Endpoint soap12Wss11(Bus bus, EchoPort service) {
        EndpointImpl endpoint = new EndpointImpl(bus, service);
        endpoint.setBindingUri(SOAPBinding.SOAP12HTTP_BINDING);

        Map<String, Object> inProps = new HashMap<>();
        inProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE );

        inProps.put(WSHandlerConstants.SIG_PROP_REF_ID, "signatureProperties");
        Properties sigProps = new Properties();
        sigProps.put("org.apache.wss4j.crypto.provider", "be.egelke.ehealth.server.mock.AllowAllCrypto");

        inProps.put("signatureProperties", sigProps);
        endpoint.getInInterceptors().add(new WSS4JInInterceptor(inProps));
        endpoint.getFeatures().add(new WSAddressingFeature());
        endpoint.publish("/echo/soap12wss11");
        return endpoint;
    }

    @Bean
    public TokenStore getTokenStore() {
        return new MemoryTokenStore();
    }

    @Bean
    public AuthClaimsParser getAuthClaimsParser() {
        return new AuthClaimsParser();
    }

    @Bean
    public ClaimsManager getClaimsManager(AuthClaimsParser claimsParser) {
        ClaimsManager claimsManager = new ClaimsManager();
        claimsManager.setClaimParsers(Collections.singletonList(claimsParser));
        return claimsManager;
    }

    @Bean
    public ServiceMBean getEchoServiceMBean() {
        StaticService staticService = new StaticService();
        List<String> endpoints = new LinkedList<>();
        endpoints.add("https://localhost:8080/services/echo/soap12wss11");
        staticService.setEndpoints(endpoints);
        staticService.setKeyType(WSS4JConstants.WST_NS_05_12 + "/PublicKey");
        staticService.setTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
        return staticService;
    }


    @Bean
    @SneakyThrows
    public SecurityTokenServiceProvider stsProvider(TokenStore tokenStore, ClaimsManager claimsManager, ServiceMBean echoServiceMBean) {
        var stsProvider = new DefaultSecurityTokenServiceProvider();
        stsProvider.setEncryptIssuedToken(false);
        stsProvider.setReturnReferences(true);
        stsProvider.setTokenStore(tokenStore);
        stsProvider.setClaimsManager(claimsManager);
        stsProvider.setStsProperties(new StaticSTSProperties());
        stsProvider.setServices(Collections.singletonList(echoServiceMBean));

        return stsProvider;
    }

    @Bean
    public Endpoint sts(Bus bus, SecurityTokenServiceProvider stsProvider) {
        EndpointImpl endpoint = new EndpointImpl(bus, stsProvider);
        endpoint.setBindingUri(SOAPBinding.SOAP12HTTP_BINDING);

        Map<String, Object> inProps = new HashMap<>();
        inProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE );

        inProps.put(WSHandlerConstants.SIG_PROP_REF_ID, "signatureProperties");
        Properties sigProps = new Properties();
        sigProps.put("org.apache.wss4j.crypto.provider", "be.egelke.ehealth.server.mock.AllowAllCrypto");

        inProps.put("signatureProperties", sigProps);
        endpoint.getInInterceptors().add(new WSS4JInInterceptor(inProps));
        endpoint.getFeatures().add(new WSAddressingFeature());

        endpoint.publish("/sts/soap12");
        return endpoint;
    }
}
