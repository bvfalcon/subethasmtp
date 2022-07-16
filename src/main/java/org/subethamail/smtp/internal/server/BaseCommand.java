package org.subethamail.smtp.internal.server;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import org.subethamail.smtp.DropConnectionException;
import org.subethamail.smtp.server.Session;

/**
 * @author Ian McFarland &lt;ian@neo.com&gt;
 * @author Jon Stevens
 * @author Jeff Schnitzer
 * @author Scott Hernandez
 */
public abstract class BaseCommand implements Command
{
	@SuppressWarnings("unused")
	private final static Logger log = Logger.getLogger(BaseCommand.class.getName());

	/** Name of the command, ie HELO */
	private final String name;
	/** The help message for this command*/
	private final HelpMessage helpMsg;

	protected BaseCommand(String name, String help)
	{
		this.name = name;
		this.helpMsg = new HelpMessage(name, help);
	}

	protected BaseCommand(String name, String help, String argumentDescription)
	{
		this.name = name;
		this.helpMsg =  new HelpMessage(name, help, argumentDescription);
	}

	/**
	 * This is the main method that you need to override in order to implement a command.
	 */
	@Override
    abstract public void execute(String commandString, Session context)
			throws IOException, DropConnectionException;

	@Override
    public HelpMessage getHelp()
	{
		return this.helpMsg;
	}

	@Override
    public String getName()
	{
		return this.name;
	}

	protected String getArgPredicate(String commandString)
	{
		if (commandString == null || commandString.length() < 4)
			return "";

		return commandString.substring(4).trim();
	}

	public static String[] getArgs(String commandString)
	{
		List<String> strings = new ArrayList<>();
		StringTokenizer stringTokenizer = new StringTokenizer(commandString);
		while (stringTokenizer.hasMoreTokens())
		{
			strings.add(stringTokenizer.nextToken());
		}

		return strings.toArray(new String[0]);
	}
}