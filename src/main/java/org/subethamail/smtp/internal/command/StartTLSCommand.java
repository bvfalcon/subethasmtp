package org.subethamail.smtp.internal.command;

import java.io.IOException;
import java.net.Socket;
import java.security.cert.Certificate;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

import org.subethamail.smtp.internal.server.BaseCommand;
import org.subethamail.smtp.server.Session;

/**
 * @author Michael Wildpaner &lt;mike@wildpaner.com&gt;
 * @author Jeff Schnitzer
 */
public final class StartTLSCommand extends BaseCommand
{
	private final static Logger log = Logger.getLogger(StartTLSCommand.class.getName());

	public StartTLSCommand()
	{
		super("STARTTLS", "The starttls command");
	}

	@Override
	public void execute(String commandString, Session sess) throws IOException
	{
		if (!commandString.trim().toUpperCase(Locale.ENGLISH).equals(this.getName()))
		{
			sess.sendResponse("501 Syntax error (no parameters allowed)");
			return;
		}

		if (!sess.getServer().getEnableTLS())
		{
			sess.sendResponse("454 TLS not supported");
			return;
		}

		try
		{
			Socket socket = sess.getSocket();
			if (socket instanceof SSLSocket)
			{
				sess.sendResponse("454 TLS not available due to temporary reason: TLS already active");
				return;
			}

			sess.sendResponse("220 Ready to start TLS");

			SSLSocket s = sess.getServer().createSSLSocket(socket);
			s.startHandshake();
			log.log(Level.FINE, "Cipher suite: " + s.getSession().getCipherSuite());

			sess.setSocket(s);
			sess.resetSmtpProtocol(); // clean state
			sess.setTlsStarted(true);

			if (s.getNeedClientAuth())
			{
				try
				{
					Certificate[] peerCertificates = s.getSession().getPeerCertificates();
					sess.setTlsPeerCertificates(peerCertificates);
				}
				catch (SSLPeerUnverifiedException e)
				{
					// IGNORE, just leave the certificate chain empty
				}
			}
		}
		catch (SSLHandshakeException ex)
		{
			// "no cipher suites in common" is common and puts a lot of crap in the logs.
			// This will at least limit it to a single WARN line and not a whole stacktrace.
			// Unfortunately it might catch some other types of SSLHandshakeException (if
			// in fact other types exist), but oh well.
			log.log(Level.WARNING, "startTLS() failed: " + ex);
		}
		catch (IOException ex)
		{
			log.log(Level.WARNING, "startTLS() failed: " + ex.getMessage(), ex);
		}
	}
}
