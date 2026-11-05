/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package io.openliberty.security.rest.jwt.fat;

import org.junit.ClassRule;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import componenttest.custom.junit.runner.AlwaysPassesTest;
import componenttest.rules.repeater.EmptyAction;
import componenttest.rules.repeater.FeatureReplacementAction;
import componenttest.rules.repeater.RepeatTests;

@RunWith(Suite.class)
@SuiteClasses({
                AlwaysPassesTest.class,
                RestJwtFATTest.class,
                RestJwtNoConnectorFATTest.class,
                RestJwtKeyFileFATTest.class,
                RestJwtKeyFileInvalidFATTest.class
})
public class FATSuite {
    public static final String REST_MBEANS_ENDPOINT = "/IBMJMXConnectorREST/mbeans";

    /*
     * EE6 (default servlet-3.1/appSecurity-2.0) runs in FULL mode only. EE9, EE10 and EE11 exercise the
     * Jakarta-transformed io.openliberty.security.rest.jwt.jakarta bundle; EE11 runs in LITE mode.
     */
    @ClassRule
    public static RepeatTests repeat = RepeatTests.with(new EmptyAction().fullFATOnly())
                    .andWith(FeatureReplacementAction.EE9_FEATURES().fullFATOnly())
                    .andWith(FeatureReplacementAction.EE10_FEATURES().fullFATOnly())
                    .andWith(FeatureReplacementAction.EE11_FEATURES());
}
