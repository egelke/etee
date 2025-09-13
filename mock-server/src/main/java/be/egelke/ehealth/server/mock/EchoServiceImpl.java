package be.egelke.ehealth.server.mock;

import org.springframework.stereotype.Service;
import test.EchoPort;

@Service
public class EchoServiceImpl implements EchoPort {

    @Override
    public String echo(String ping) {
        return ping;
    }
}
