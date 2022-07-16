package org.subethamail.smtp.internal.server;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.subethamail.smtp.DropConnectionException;
import org.subethamail.smtp.server.Session;

/**
 * This class manages execution of a SMTP command.
 *
 * @author Jon Stevens
 * @author Scott Hernandez
 */
public final class CommandHandler {
    private final static Logger log = Logger.getLogger(CommandHandler.class.getName());

    /**
     * The map of known SMTP commands. Keys are upper case names of the
     * commands.
     */
    private final Map<String, Command> commandMap = new HashMap<String, Command>();

    public CommandHandler() {
        // This solution should be more robust than the earlier "manual"
        // configuration.
        for (CommandRegistry registry : CommandRegistry.values()) {
            this.addCommand(registry.getCommand());
        }
    }

    /**
     * Create a command handler with a specific set of commands.
     *
     * @param availableCommands
     *            the available commands (not null) TLS note: wrap commands with
     *            {@link RequireTLSCommandWrapper} when appropriate.
     */
    public CommandHandler(Collection<Command> availableCommands) {
        for (Command command : availableCommands) {
            this.addCommand(command);
        }
    }

    /**
     * Adds or replaces the specified command.
     */
    public void addCommand(Command command) {
    	log.log(Level.FINE, "Added command: {0}", command.getName());

        this.commandMap.put(command.getName(), command);
    }

    /**
     * Returns the command object corresponding to the specified command name.
     * 
     * @param commandName
     *            case insensitive name of the command.
     * @return the command object, or null, if the command is unknown.
     */
    public Command getCommand(String commandName) {
        String upperCaseCommandName = commandName.toUpperCase(Locale.ENGLISH);
        return this.commandMap.get(upperCaseCommandName);
    }

    public boolean containsCommand(String command) {
        return this.commandMap.containsKey(command);
    }

    public Set<String> getVerbs() {
        return this.commandMap.keySet();
    }

    public void handleCommand(Session context, String commandString)
            throws SocketTimeoutException, IOException, DropConnectionException {
        try {
            Command command = getCommandFromString(commandString);
            command.execute(commandString, context);
        } catch (CommandException e) {
            context.sendResponse("500 " + e.getMessage());
        }
    }

    /**
     * @return the HelpMessage object for the given command name (verb)
     * @throws CommandException
     */
    public HelpMessage getHelp(String command) throws CommandException {
        return getCommandFromString(command).getHelp();
    }

    private Command getCommandFromString(String commandString)
            throws UnknownCommandException, InvalidCommandNameException {
        Command command = null;
        String key = toKey(commandString);
        if (key != null) {
            command = this.commandMap.get(key);
        }
        if (command == null) {
            // some commands have a verb longer than 4 letters
            String verb = toVerb(commandString);
            if (verb != null) {
                command = this.commandMap.get(verb);
            }
        }
        if (command == null) {
            throw new UnknownCommandException("Error: command not implemented");
        }
        return command;
    }

    private static String toKey(String string) throws InvalidCommandNameException {
        if (string == null || string.length() < 4)
            throw new InvalidCommandNameException("Error: bad syntax");

        return string.substring(0, 4).toUpperCase(Locale.ENGLISH);
    }

    private static String toVerb(String string) throws InvalidCommandNameException {
        StringTokenizer stringTokenizer = new StringTokenizer(string);
        if (!stringTokenizer.hasMoreTokens())
            throw new InvalidCommandNameException("Error: bad syntax");

        return stringTokenizer.nextToken().toUpperCase(Locale.ENGLISH);
    }
}
