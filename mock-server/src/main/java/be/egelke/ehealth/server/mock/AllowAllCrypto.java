package be.egelke.ehealth.server.mock;

import lombok.extern.slf4j.Slf4j;
import org.apache.wss4j.common.crypto.CryptoBase;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Properties;
import java.util.regex.Pattern;

@Slf4j
public class AllowAllCrypto extends CryptoBase {

    public AllowAllCrypto(Properties properties, ClassLoader loader, PasswordEncryptor passwordEncryptor) {

    }

    @Override
    public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
        throw new IllegalStateException("We don not support getting x509 certs");
    }

    @Override
    public String getX509Identifier(X509Certificate x509Certificate) throws WSSecurityException {
        throw new IllegalStateException("We don not support getting ids of x509 certs");
    }

    @Override
    public PrivateKey getPrivateKey(X509Certificate x509Certificate, CallbackHandler callbackHandler) throws WSSecurityException {
        throw new IllegalStateException("not private key supported");
    }

    @Override
    public PrivateKey getPrivateKey(PublicKey publicKey, CallbackHandler callbackHandler) throws WSSecurityException {
        throw new IllegalStateException("not private key supported");
    }

    @Override
    public PrivateKey getPrivateKey(String s, String s1) throws WSSecurityException {
        throw new IllegalStateException("not private key supported");
    }

    @Override
    public void verifyTrust(X509Certificate[] x509Certificates, boolean b, Collection<Pattern> collection, Collection<Pattern> collection1) throws WSSecurityException {
        log.info("allow all certs of the following chain:");
        for(X509Certificate cert : x509Certificates) {
            log.info("\t{} [Key={}]", cert.getSubjectX500Principal(), cert.getPublicKey().getAlgorithm());
        }
    }

    @Override
    public void verifyTrust(PublicKey publicKey) throws WSSecurityException {
        throw new IllegalStateException("not raw public keys supported");
    }
}
