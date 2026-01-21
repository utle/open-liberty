/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package io.openliberty.mcp.internal.fat.introspector;

import static com.ibm.websphere.simplicity.ShrinkHelper.DeployOptions.SERVER_ONLY;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.ProgramOutput;
import com.ibm.websphere.simplicity.ShrinkHelper;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;
import io.openliberty.mcp.internal.fat.tool.basicToolApp.BasicTools;

/**
 *
 */
@RunWith(FATRunner.class)
public class IntrospectorTest {

    @Server("mcp-server")
    public static LibertyServer server;

    @BeforeClass
    public static void setup() throws Exception {
        WebArchive war = ShrinkWrap.create(WebArchive.class, "introspector.war")
                                   .addPackage(BasicTools.class.getPackage());

        ShrinkHelper.exportDropinAppToServer(server, war, SERVER_ONLY);

        server.startServer();
    }

    @AfterClass
    public static void teardown() throws Exception {
        server.stopServer();
    }

    @Test
    public void testDumpServerTriggersMcpIntrospector() throws Exception {

        // Trigger server dump
        ProgramOutput output = server.serverDump(null);
        String stdout = output.getStdout();

        // Extract dump zip path
        Pattern zipPathPattern = Pattern.compile("dump complete in (.*?\\.zip)\\.");
        Matcher matcher = zipPathPattern.matcher(stdout);
        assertTrue("Could not find dump zip path in stdout", matcher.find());

        String zipFilePath = matcher.group(1);

        // Open dump zip and locate MCPIntrospector.txt
        try (ZipFile zip = new ZipFile(zipFilePath)) {
            ZipEntry introspectorEntry = null;

            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith("MCPIntrospector.txt")) {
                    introspectorEntry = entry;
                    break;
                }
            }

            assertNotNull("MCPIntrospector.txt not found in dump zip", introspectorEntry);

            // Read introspector output
            StringBuilder contents = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                                                            new java.io.InputStreamReader(zip.getInputStream(introspectorEntry), StandardCharsets.UTF_8))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    contents.append(line).append('\n');
                }
            }

            String introspectorText = contents.toString();

            assertTrue("Expected MCP introspection header not found",
                       introspectorText.contains("=== MCP Tool Introspection ==="));

            assertTrue("Expected application entry not found",
                       introspectorText.contains("Application:"));

            assertTrue("Expected at least one tool entry",
                       introspectorText.contains("Tool:"));
        }
    }

}