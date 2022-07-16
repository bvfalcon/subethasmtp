package org.subethamail.smtp.internal.proxy;

import static org.subethamail.smtp.internal.util.HexUtils.toHex;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.subethamail.smtp.server.Session;

/**
 * Implements {@link ProxyHandler} both for <a href="https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt">PROXY
 * protocol V1 textual and V2 binary</a>.
 *
 * @author Diego Salvi
 */
public class ProxyProtocolV1V2Handler implements ProxyHandler {

    private final static Logger log = Logger.getLogger(ProxyProtocolV1V2Handler.class.getName());

    /** Standard instance */
    public static final ProxyProtocolV1V2Handler INSTANCE =
            new ProxyProtocolV1V2Handler(ProxyProtocolV1Handler.INSTANCE, ProxyProtocolV2Handler.INSTANCE);

    ProxyProtocolV1Handler v1;
    ProxyProtocolV2Handler v2;

    public ProxyProtocolV1V2Handler(ProxyProtocolV1Handler v1, ProxyProtocolV2Handler v2) {
        this.v1 = v1;
        this.v2 = v2;
    }

    @Override
    public ProxyResult handle(InputStream in, OutputStream out, Session session) throws IOException {

        // Max bytes to peek from stream to check for PROXY protocol header prefix
        int maxPrefixSize = Math.max(ProxyProtocolV1Handler.prefixSize(), ProxyProtocolV2Handler.prefixSize());

        // Do NOT close this buffer or will close wrapped IO
        BufferedInputStream buffered = new BufferedInputStream(in, maxPrefixSize);

        // Setup a read ahead limit. We'll use this stream to parse PROXY headers if a right prefix has been detected
        buffered.mark(maxPrefixSize);

        byte[] prefix = new byte[maxPrefixSize];
        int read = buffered.read(prefix, 0, maxPrefixSize);


        if (v1.isValidPrefix(prefix)) {
        	log.log(Level.FINE, "(session {0}) Detected PROXY protocol v1 prefix", session.getSessionId());
            buffered.reset();
            return v1.handle(buffered, out, session);
        }

        if (v2.isValidPrefix(prefix)) {
        	log.log(Level.FINE, "(session {0}) Detected PROXY protocol v2 prefix", session.getSessionId());
            buffered.reset();
            return v2.handle(buffered, out, session);
        }

        String prefixHex = toHex(prefix, 0, read);
        log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v1 or v2 prefix {1}", new Object[] { session.getSessionId(), prefixHex });
        throw new IOException("Invalid PROXY protocol v1 or v2 prefix " + prefixHex);

    }

}
