/*******************************************************************************
 * Copyright (c) 2017, 2018 IBM Corporation and others.
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
package com.ibm.ws.webcontainer.collaborator;

import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.websphere.security.WSSecurityException;
import com.ibm.websphere.security.auth.WSSubject;
import com.ibm.wsspi.webcontainer.WCCustomProperties;
import com.ibm.wsspi.webcontainer.collaborator.IWebAppSecurityCollaborator;
import com.ibm.wsspi.webcontainer.extension.ExtensionProcessor;
import com.ibm.wsspi.webcontainer.security.SecurityViolationException;
import com.ibm.wsspi.webcontainer.servlet.IExtendedRequest;
import com.ibm.wsspi.webcontainer.servlet.IServletContext;
import com.ibm.wsspi.webcontainer.logging.LoggerFactory;

public class WebAppSecurityCollaborator implements IWebAppSecurityCollaborator {
    private static final String CLASS_NAME="com.ibm.ws.webcontainer.collaborator.WebAppSecurityCollaborator";
    protected static Logger logger = LoggerFactory.getInstance().getLogger("com.ibm.ws.webcontainer.collaborator");
    

    public Object preInvoke(HttpServletRequest req, HttpServletResponse resp,
                            String servletName, boolean enforceSecurity)
                        throws SecurityViolationException, IOException {

        System.out.println("<<UTLE>> preInvoke (1) Caller Subject on thread? enforceSecurity: "+ enforceSecurity);
        try {
            System.out.println("<<UTLE>> preInvoke (1) Caller Subject on thread? " + WSSubject.getCallerSubject());
            //if (WSSubject.getCallerPrincipal() != null) {
            //    WSSubject.setCallerSubject(null);
            //    System.out.println("<<UTLE>> preInvoke (1) After clear Subject on thread: " + WSSubject.getCallerSubject());
            //}
        } catch (WSSecurityException e) {
            // TODO Auto-generated catch block
            // Do you need FFDC here? Remember FFDC instrumentation and @FFDCIgnore
            e.printStackTrace();
        }
        
        //don't allow default "TRACE" request by default - even when security is disabled
        String defaultMethod = (String) req.getAttribute("com.ibm.ws.webcontainer.security.checkdefaultmethod");
        
        if ("TRACE".equals(defaultMethod) && !WCCustomProperties.ENABLE_TRACE_REQUESTS) {
            //in the security code, the cause exception is a deny reply
            Exception exceptionSentToHandleException = new Exception("IBMWebContainerTraceRequestException");
            SecurityViolationException secVE = new SecurityViolationException("Illegal request. Default implementation of TRACE not allowed.", HttpServletResponse.SC_FORBIDDEN);
            secVE.initCause(exceptionSentToHandleException);
            throw secVE;
        }
        return null;
    }

    public Object preInvoke(String servletName)
                        throws SecurityViolationException, IOException {
        System.out.println("<<UTLE>> preInvoke (2) Caller Subject on thread? ");
        try {
            System.out.println("<<UTLE>> preInvoke (2) Caller Subject on thread? " + WSSubject.getCallerSubject());
        } catch (WSSecurityException e) {
            // TODO Auto-generated catch block
            // Do you need FFDC here? Remember FFDC instrumentation and @FFDCIgnore
            e.printStackTrace();
        }
        return null;
    }

    public Object preInvoke() throws SecurityViolationException {
        System.out.println("<<UTLE>> preInvoke (3) Caller Subject on thread? ");
        try {
            System.out.println("<<UTLE>> preInvoke (3) Caller Subject on thread? " + WSSubject.getCallerSubject());
        } catch (WSSecurityException e) {
            // TODO Auto-generated catch block
            // Do you need FFDC here? Remember FFDC instrumentation and @FFDCIgnore
            e.printStackTrace();
        }
        //if (com.ibm.ejs.ras.TraceComponent.isAnyTracingEnabled()&&logger.isLoggable (Level.FINE)){
            logger.entering(CLASS_NAME,"preInvoke");
        //}
        clearSubjectsOnThread();
        //if (com.ibm.ejs.ras.TraceComponent.isAnyTracingEnabled()&&logger.isLoggable (Level.FINE)){
            logger.exiting(CLASS_NAME,"preInvoke");
        //}
        return null;
    }

    public void postInvokeForSecureResponse(Object secObject) throws ServletException {
        // TODO Auto-generated method stub
    }
    
    public void postInvoke(Object secObject) throws ServletException {
        // TODO Auto-generated method stub
    }

    public void handleException(HttpServletRequest req,
                                HttpServletResponse rsp, Throwable wse)
                        throws ServletException, IOException {
        //this is typically overridden within the security code.
        if (wse!=null && "IBMWebContainerTraceRequestException".equals(wse.getMessage())) {
            //this message is the same non-translated message that security reports when security is enabled
            rsp.sendError(HttpServletResponse.SC_FORBIDDEN, "Illegal request. Default implementation of TRACE not allowed.");
        }
    }

    public Principal getUserPrincipal() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isCDINeeded() {
        // TODO Auto-generated method stub
        return false;
    }

    public boolean isUserInRole(String role, IExtendedRequest req) {
        // TODO Auto-generated method stub
        return false;
    }

    public ExtensionProcessor getFormLoginExtensionProcessor(
                                                             IServletContext webapp) {
        // TODO Auto-generated method stub
        return null;
    }

    public ExtensionProcessor getFormLogoutExtensionProcessor(
                                                              IServletContext webapp) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean authenticate(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void login(HttpServletRequest req, HttpServletResponse resp, String username, String password) throws ServletException {
    // TODO Auto-generated method stub

    }

    @Override
    public void logout(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
    // TODO Auto-generated method stub

    }

    @Override
    public List<String> getURIsInSecurityConstraints(String appName,
                                                     String contextRoot, String host, List<String> URIs) {
        return null;
    }
    
    private void clearSubjectsOnThread() {
        try {
         
            /*
            final SubjectManager sm = SubjectManager.getSubjectManager();
            
            if (sm != null) {
                AccessController.doPrivileged(new PrivilegedAction<Object>() {
                    @Override
                    public Object run() {
                        sm.setInvocationSubject(null);
                        sm.setCallerSubject(null);
                        return null;
                    }
                });
            } else {
                WSSubject.setRunAsSubject(null);
            } */
            //if (com.ibm.ejs.ras.TraceComponent.isAnyTracingEnabled()&&logger.isLoggable (Level.FINE)){
                logger.exiting(CLASS_NAME,"clearSubjectsOnThread callerSubject: "+  WSSubject.getCallerSubject() + " runAsSubject: " + WSSubject.getRunAsSubject());
            //}
            System.out.println("<<UTLE>> Caller Subject on thread? " + WSSubject.getCallerSubject());
            System.out.println("<<UTLE>> RunAs Subject on thread? " + WSSubject.getRunAsSubject());
            System.err.println("<<UTLE>> Failed to clear security subjects on thread: ");
            WSSubject.setRunAsSubject(null);
        } catch (Exception e) {
            System.err.println("Failed to clear security subjects on thread: " + e.getMessage());
        }
    }
}
