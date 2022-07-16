package org.subethamail.smtp.internal.proxy;

import static org.subethamail.smtp.internal.util.HexUtils.toHex;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.subethamail.smtp.internal.util.ArrayUtils;
import org.subethamail.smtp.server.Session;

/**
 * Implements {@link ProxyHandler} for <a href="https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt">PROXY
 * protocol V1 textual</a>.
 *
 * @author Diego Salvi
 */
public class ProxyProtocolV1Handler implements ProxyHandler {

    private final static Logger log = Logger.getLogger(ProxyProtocolV1Handler.class.getName());

    public static final ProxyProtocolV1Handler INSTANCE = new ProxyProtocolV1Handler();

    /**
     * Maximum PROXY header length
     */
    public static final int MAX_PROXY_HEADER_LENGTH = 107;

    /**
     * PROXY header prefix: "PROXY "
     */
    private static final byte[] PREFIX = "PROXY ".getBytes(StandardCharsets.US_ASCII);

    private static final Pattern PATTERN = Pattern.compile("PROXY (?<family>UNKNOWN|TCP4|TCP6)"
            + "( (?<asrc>[0-9a-fA-F.:]+) (?<adst>[0-9a-fA-F.:]+) (?<psrc>[0-9]{1,5}) (?<pdst>[0-9]{1,5}))?\r\n");

    public enum Family {
        UNKNOWN,
        TCP4,
        TCP6
    }

    /* States for PROXY header reading */
    
    /** Header still in reading */
    private static final int STATE_READING = 0;
    
    /** Found a CR, looking for a LF */
    private static final int STATE_READ_TERMINATING = 1;
    
    /** Found CRLF, reading concluded */
    private static final int STATE_READ_END = 2;
    
    /** Found ad invalid sequence, reading failed */
    private static final int STATE_READ_ERROR = 3;
    
    private ProxyProtocolV1Handler() {
    }

    /**
     * Returns the PROXY protocol v1 prefix size, it can be used to retrieve data from connection and then invoke
     * {@link #isValidPrefix(byte[])}.
     *
     * @return PROXY protocol v1 prefix size
     */
    static int prefixSize() {
        return PREFIX.length;
    }

    /**
     * Check if given prefix is a PROXY protocol v1 prefix. Only the prefix will be checked: it doesn't check any other
     * data following the prefix
     *
     * @param prefix byte array prefix to isValidPrefix
     * @return {@code true} if is a PROXY protocol v1 prefix
     */
    boolean isValidPrefix(byte[] prefix) {
        return prefix.length >= PREFIX.length // Must accomodate every prefix byte
                && ArrayUtils.equals(PREFIX, 0, PREFIX.length, prefix, 0, PREFIX.length);
    }

    @Override
    public ProxyResult handle(InputStream in, OutputStream out, Session session) throws IOException {

        /*
         * Header as seen on specs
         *
         * - a string identifying the protocol : "PROXY" ( \x50 \x52 \x4F \x58 \x59 ) Seeing this string indicates that
         * this is version 1 of the protocol.
         *
         * - exactly one space : " " ( \x20 )
         *
         * - a string indicating the proxied INET protocol and family. As of version 1, only "TCP4" ( \x54 \x43 \x50
         * \x34 ) for TCP over IPv4, and "TCP6" ( \x54 \x43 \x50 \x36 ) for TCP over IPv6 are allowed. Other,
         * unsupported, or unknown protocols must be reported with the name "UNKNOWN" ( \x55 \x4E \x4B \x4E \x4F \x57
         * \x4E ). For "UNKNOWN", the rest of the line before the CRLF may be omitted by the sender, and the receiver
         * must ignore anything presented before the CRLF is found. Note that an earlier version of this specification
         * suggested to use this when sending health checks, but this causes issues with servers that reject the
         * "UNKNOWN" keyword. Thus is it now recommended not to send "UNKNOWN" when the connection is expected to be
         * accepted, but only when it is not possible to correctly fill the PROXY line.
         *
         * - exactly one space : " " ( \x20 )
         *
         * - the layer 3 source address in its canonical format. IPv4 addresses must be indicated as a series of exactly
         * 4 integers in the range [0..255] inclusive written in decimal representation separated by exactly one dot
         * between each other. Heading zeroes are not permitted in front of numbers in order to avoid any possible
         * confusion with octal numbers. IPv6 addresses must be indicated as series of sets of 4 hexadecimal digits
         * (upper or lower case) delimited by colons between each other, with the acceptance of one double colon
         * sequence to replace the largest acceptable range of consecutive zeroes. The total number of decoded bits must
         * exactly be 128. The advertised protocol family dictates what format to use.
         *
         *
         * - exactly one space : " " ( \x20 )
         *
         *
         * - the layer 3 destination address in its canonical format. It is the same format as the layer 3 source
         * address and matches the same family.
         *
         *
         * - exactly one space : " " ( \x20 )
         *
         *
         * - the TCP source port represented as a decimal integer in the range [0..65535] inclusive. Heading zeroes are
         * not permitted in front of numbers in order to avoid any possible confusion with octal numbers.
         *
         *
         * - exactly one space : " " ( \x20 )
         *
         *
         *
         * - the TCP destination port represented as a decimal integer in the range [0..65535] inclusive. Heading zeroes
         * are not permitted in front of numbers in order to avoid any possible confusion with octal numbers.
         *
         *
         * - the CRLF sequence ( \x0D \x0A )
         *
         */
        log.log(Level.FINE, "(session {0}) Starting PROXY protocol v1 handling", session.getSessionId());

        byte[] header = new byte[MAX_PROXY_HEADER_LENGTH];
        int len = in.read(header, 0, PREFIX.length);
        if (len != PREFIX.length) {
            final String headerHex = toHex(header, 0, len);
            log.log(Level.SEVERE, "(session {0}) Failed to fully read PROXY v1 header prefix. Read {1}",
                    new Object[] { session.getSessionId(), headerHex });
            return ProxyResult.FAIL;
        }

        if (!ArrayUtils.equals(PREFIX, 0, PREFIX.length, header, 0, PREFIX.length)) {
            final String receivedHeader = toHex(header, 0, len);
            log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v1 header prefix {1}", new Object[] { session.getSessionId(), receivedHeader });
            return ProxyResult.FAIL;
        }

        int state = STATE_READING;
        while (state < STATE_READ_END && len < MAX_PROXY_HEADER_LENGTH) {
            int read = in.read();
            if (read < 0) {
                final String headerHex = toHex(header, 0, len);
                log.log(Level.SEVERE, "(session {0}) Failed to fully read PROXY v1 header. Read {1}",
                        new Object[] { session.getSessionId(), headerHex });
                return ProxyResult.FAIL;
            }

            byte result = (byte) read;
            header[len++] = result;

            switch (state) {
                case STATE_READING:
                    // Check for CR
                    if (read == 0x0D) {
                        state = STATE_READ_TERMINATING;
                    }
                    break;
                case STATE_READ_TERMINATING:
                    // Check for LF
                    if (read == 0x0A) {
                        // Termination
                        state = STATE_READ_END;
                    } else {
                        state = STATE_READ_ERROR;
                    }
                    break;
                default:
                    // State unexpected
                    state = STATE_READ_ERROR;
            }
        }

        final String headerHex = toHex(header, 0, len);
        log.log(Level.FINE, "(session {0}) Read header {1}", new Object[] { session.getSessionId(), headerHex });

        // Check if header read terminated due to max length reached without find a wellformed termination
        if (state != STATE_READ_END) {
            log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v1 header {1}", new Object[] { session.getSessionId(), headerHex });
            return ProxyResult.FAIL;
        }

        Matcher matcher = PATTERN.matcher(new String(header, 0, len, StandardCharsets.US_ASCII));
        if (!matcher.matches()) {
            log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v1 header {1}", new Object[] { session.getSessionId(), headerHex });
            return ProxyResult.FAIL;
        }

        InetSocketAddress clientAddress;

        // By regex definition family MUST exists and be one of UNKNOWN, TCP4 or TCP6
        String family = matcher.group("family");
        switch (family) {
            case "UNKNOWN":
                return ProxyResult.NOP;
            case "TCP4": {
                String asrc = matcher.group("asrc");
                if (asrc == null) {
                    /*
                     * We need to isValidPrefix only for one group between asrc, adst, psrc or pdst. Ther are all or
                     * noting by regex definition.
                     */
                    log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v1 header {1}", new Object[] { session.getSessionId(), headerHex });
                    return ProxyResult.FAIL;
                }

                InetAddress src;
                try {
                    src = InetAddress.getByName(asrc);
                } catch (UnknownHostException ex) {
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v1 source IPv4 {1}", new Object[] { session.getSessionId(), asrc });
                    return ProxyResult.FAIL;
                }

                if (!(src instanceof Inet4Address)) {
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v1 source IPv4 {1}", new Object[] { session.getSessionId(), asrc });
                    return ProxyResult.FAIL;
                }

                // Group psrc cannot be null here
                int psrc = Integer.parseInt(matcher.group("psrc"));
                if (psrc < 1 || psrc > 65535) {
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v1 source IPv4 port {1}", new Object[] { session.getSessionId(), psrc });
                    return ProxyResult.FAIL;
                }
                clientAddress = new InetSocketAddress(src, psrc);
                break;
            }

            case "TCP6": {
                String asrc = matcher.group("asrc");
                if (asrc == null) {
                    /*
                     * We need to isValidPrefix only for one group between asrc, adst, psrc or pdst. Ther are all or
                     * noting by regex definition.
                     */
                    log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v1 header {1}", new Object[] { session.getSessionId(), headerHex });
                    return ProxyResult.FAIL;
                }

                InetAddress src;
                try {
                    src = InetAddress.getByName(asrc);
                } catch (UnknownHostException ex) {
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v1 source IPv6 {1}", new Object[] { session.getSessionId(), asrc });
                    return ProxyResult.FAIL;
                }

                if (!(src instanceof Inet6Address)) {
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v1 source IPv6 {1}", new Object[] { session.getSessionId(), asrc });
                    return ProxyResult.FAIL;
                }

                // Group psrc cannot be null here
                int psrc = Integer.parseInt(matcher.group("psrc"));
                if (psrc < 1 || psrc > 65535) {
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v1 source IPv6 port {1}", new Object[] { session.getSessionId(), psrc });
                    return ProxyResult.FAIL;
                }
                clientAddress = new InetSocketAddress(src, psrc);
                break;
            }
            default:
                // Due to regex we should never end here
                log.log(Level.SEVERE, "(session {0}) Unknown PROXY protocol v1 address family {1}", new Object[] { session.getSessionId(), family });
                return ProxyResult.FAIL;
        }

        log.log(Level.FINE, "(session {0}) Accepted PROXY connection: family {1} client {2} original {3}",
                new Object[] { session.getSessionId(), family, clientAddress.getHostString(),
                session.getRealRemoteAddress().getHostString() });

        return new ProxyResult(clientAddress);
    }

}
