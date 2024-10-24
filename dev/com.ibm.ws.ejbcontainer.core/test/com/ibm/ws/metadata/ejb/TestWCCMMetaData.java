/*******************************************************************************
 * Copyright (c) 2014 IBM Corporation and others.
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
package com.ibm.ws.metadata.ejb;

import com.ibm.tx.jta.embeddable.GlobalTransactionSettings;
import com.ibm.tx.jta.embeddable.LocalTransactionSettings;
import com.ibm.ws.resource.ResourceRefConfigList;

public class TestWCCMMetaData extends WCCMMetaData {
    @Override
    public ResourceRefConfigList createResRefList() {
        return null;
    }

    @Override
    public LocalTransactionSettings createLocalTransactionSettings() {
        return null;
    }

    @Override
    public GlobalTransactionSettings createGlobalTransactionSettings() {
        return null;
    }
}
