/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa;

/**
 * Exception thrown when LTPA keystore operations fail.
 */
public class LTPAKeystoreException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new LTPAKeystoreException with the specified detail message.
     *
     * @param message the detail message
     */
    public LTPAKeystoreException(String message) {
        super(message);
    }

    /**
     * Constructs a new LTPAKeystoreException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause
     */
    public LTPAKeystoreException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Made with Bob
