package be.egelke.ehealth.server.mock;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class App {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(App.class, args);
    }
}
