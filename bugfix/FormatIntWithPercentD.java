package com.amazon.rds.bourne.connector.controlplaneapi.patching.serviceconfigurator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FormatIntWithPercentD {
    private static final Logger LOG = LoggerFactory.getLogger(VMWApplianceConfigurationHelper.class);

    public void runProcess(final ProcessBuilder pb, final String successOutput) {
        int exitValue;
        Process p = null;
        final StringBuilder stdoutSB = new StringBuilder();
        final StringBuilder stderrSB = new StringBuilder();
        boolean isConfigured = false;
        try {
            p = pb.start();
            try (BufferedReader stdoutBR = new BufferedReader(new InputStreamReader(p.getInputStream(),
                    StandardCharsets.UTF_8));
                 BufferedReader stderrBR = new BufferedReader(new InputStreamReader(p.getErrorStream(),
                         StandardCharsets.UTF_8))) {
                String line;
                while ((line = stdoutBR.readLine()) != null) {
                    stdoutSB.append(line);
                    stdoutSB.append("\n");
                    if (StringUtils.equalsIgnoreCase(line, successOutput)) {
                        isConfigured = true;
                    }
                }

                while ((line = stderrBR.readLine()) != null) {
                    stderrSB.append(line);
                    stderrSB.append("\n");
                }

                exitValue = p.waitFor();
            }
        } catch (final Exception e) {
            throw new RuntimeException("Got exception running process to configure VMW appliance.", e);
        } finally {
            try {
                if (p != null) {
                    p.destroy();
                    if (p.getInputStream() != null) {
                        p.getInputStream().close();
                    }
                    if (p.getOutputStream() != null) {
                        p.getOutputStream().close();
                    }
                    if (p.getErrorStream() != null) {
                        p.getErrorStream().close();
                    }
                }
            } catch (final IOException e) {
                LOG.warn("Got exception in closing process streams", e);
            }
        }

        if (exitValue != 0 || !isConfigured) {
            final String msg = String.format(
                    "Process did not complete successfully. Exit value [%s]. stdout [%s]. stderr[%s].",
                    exitValue, stdoutSB.toString(), stderrSB.toString());
            throw new RuntimeException(msg);
        } else {
            LOG.info("VMW appliance configured successfully. stdout [{}]. stderr [{}].", stdoutSB.toString(),
                    stderrSB.toString());
        }
    }
}