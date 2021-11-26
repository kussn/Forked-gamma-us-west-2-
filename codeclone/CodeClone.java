package com.amazonaws.hermes.agent.telemetry.ssm;

import com.amazonaws.hermes.agent.exceptions.ExecutionFailedException;
import com.amazonaws.hermes.agent.exceptions.LogFileReadingException;
import com.amazonaws.hermes.agent.exceptions.UnsupportedOSException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.inject.Inject;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public class SSMLogAnalyser {

    private static final Logger LOGGER = LogManager.getLogger(SSMLogAnalyser.class);

    private SSMCommandsUtils ssmCommandsUtils;

    private static final String SSM_AGENT_LOG_FILE_PATH = "/var/log/amazon/ssm/amazon-ssm-agent.log";
    private static final String SSM_HIBERNATE_LOG_FILE_PATH = "/var/log/amazon/ssm/hibernate.log";
    private static final String SSM_AGENT_HEALTH_CHECK_MESSAGE = "HealthCheck reporting agent health.";
    private static final String SSM_AGENT_HIBERNATION_MESSAGE = "Agent is in hibernate mode";

    @Inject
    public SSMLogAnalyser(SSMCommandsUtils ssmCommandsUtils){
        this.ssmCommandsUtils = ssmCommandsUtils;
    }

    public boolean checkAgentIsHibernating() throws LogFileReadingException, ExecutionFailedException, UnsupportedOSException {
        LOGGER.debug("Comparing logs to check if agent is hibernating...");
        final Instant healthCheck = getLastHealthCheckTimeStamp();
        final Instant hibernation = getLastAgentHibernateTimeStamp();

        if (healthCheck == null) {
            final String error = String.format("Agent health check log line was not found in log file: [%s]",
                    SSM_AGENT_LOG_FILE_PATH);
            throw new LogFileReadingException(error);
        }
        if (hibernation == null) {
            LOGGER.error(String.format("Agent hibernation log line was not found in log file: [%s]",
                    SSM_HIBERNATE_LOG_FILE_PATH));
        }

        // if there are no hibernation log, then agent never hibernated
        return hibernation != null && hibernation.compareTo(healthCheck) >= 0;
    }

    private Instant getLastHealthCheckTimeStamp() throws LogFileReadingException, ExecutionFailedException,
            UnsupportedOSException {
        final String line = findLatestMessageInFile(SSM_AGENT_HEALTH_CHECK_MESSAGE, SSM_AGENT_LOG_FILE_PATH);
        if (line == null) {
            return null;
        }

        final String timestamp = getTimeStamp(line);
        LOGGER.debug(String.format("Last SSM Agent HealthCheck occurred on [%s]", timestamp));
        return parseDateFromString(timestamp);
    }

    private Instant getLastAgentHibernateTimeStamp() throws LogFileReadingException, ExecutionFailedException, UnsupportedOSException {
        final String line = findLatestMessageInFile(SSM_AGENT_HIBERNATION_MESSAGE, SSM_HIBERNATE_LOG_FILE_PATH);
        if (line == null) {
            return null;
        }

        final String timestamp = getTimeStamp(line);
        LOGGER.debug(String.format("Last SSM Agent hibernated occurred on [%s]", timestamp));
        return parseDateFromString(timestamp);
    }

    private String findLatestMessageInFile(final String message, final String filepath) throws ExecutionFailedException, UnsupportedOSException {
        try {
            LOGGER.debug(String.format("Searching last occurrence of [%s] in log file: [%s]", message,
                    StringUtils.substringAfterLast(filepath, "/")));
            return ssmCommandsUtils.grepLastOccurrenceInFile(message, filepath);
        } catch (ExecutionFailedException ex) {
            final String error = String.format("Received exception while trying to find message: [%s] in log file: " +
                    "[%s]", message, StringUtils.substringAfterLast(filepath, "/"));
            throw new ExecutionFailedException(error, ex);
        }
    }

    private static String getTimeStamp(final String logLine) throws LogFileReadingException {
        final String[] info = StringUtils.split(logLine, " ", 4);
        if (info.length < 4) {
            final String error = String.format("Unknown log format, Log line: [%s]", logLine);
            throw new LogFileReadingException(error);
        }
        return StringUtils.join(info[0], " " , info[1]);
    }

    private static Instant parseDateFromString(final String timestamp) throws LogFileReadingException {
        try {
            final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            final LocalDateTime localDateTime = LocalDateTime.from(dateTimeFormatter.parse(timestamp));
            final ZonedDateTime zonedDateTime = ZonedDateTime.of(localDateTime, ZoneId.systemDefault());
            return validateLogTimeStamp(Instant.from(zonedDateTime));
        } catch (DateTimeParseException ex) {
            final String error = String.format("There was a problem when parsing timestamp [%s] to a Instant object",
                    timestamp);
            throw new LogFileReadingException(error, ex);
        }
    }

    /**
     * As instance timezone might change, we want to make sure mini-agent consume log within correct timezone.
     *   - If instance timezone was set backwards (i.e. from 9AM to 7AM), then we will invalidate the log by
     *   comparing it to current time. If the log is in the future, then it was not logged after timezone change.
     *   i.e. invalid. It also means that no new log have appeared after timezone change (i.e. instance reboot),
     *   therefore, we will return null if log time is greater than current time.
     *
     *   - If instance timezone was set forwards (i.e. from 7AM to 9AM), SSM agent still logs as expected.
     *
     * @param timestamp a Date object to be validated
     * @return the Date object if it is valid, null if it is invalid
     */
    private static Instant validateLogTimeStamp(final Instant timestamp) {
        return timestamp.compareTo(Instant.now()) < 0 ? timestamp : null;
    }
}