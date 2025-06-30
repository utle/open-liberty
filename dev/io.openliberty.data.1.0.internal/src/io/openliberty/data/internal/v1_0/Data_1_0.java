/*******************************************************************************
 * Copyright (c) 2024,2025 IBM Corporation and others.
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
package io.openliberty.data.internal.v1_0;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.util.Set;

import javax.sql.DataSource;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;

import com.ibm.websphere.ras.annotation.Trivial;

import io.openliberty.data.internal.version.DataVersionCompatibility;
import jakarta.data.Limit;
import jakarta.data.Order;
import jakarta.data.Sort;
import jakarta.data.page.PageRequest;
import jakarta.data.repository.Delete;
import jakarta.data.repository.Find;
import jakarta.data.repository.Insert;
import jakarta.data.repository.Query;
import jakarta.data.repository.Save;
import jakarta.data.repository.Update;
import jakarta.persistence.EntityManager;

/**
 * Capability that is specific to the version of Jakarta Data.
 */
@Component(configurationPid = "io.openliberty.data.internal.version.1.0",
           configurationPolicy = ConfigurationPolicy.IGNORE,
           service = DataVersionCompatibility.class)
public class Data_1_0 implements DataVersionCompatibility {

    /**
     * Annotations that represent lifecycle operations that are allowed for
     * methods of a stateful repository.
     */
    private static final Set<Class<? extends Annotation>> LIFECYCLE_ANNOS_STATEFUL = //
                    Set.of();

    /**
     * Annotations that represent lifecycle operations that are allowed for
     * methods of a stateless repository.
     */
    private static final Set<Class<? extends Annotation>> LIFECYCLE_ANNOS_STATELESS = //
                    Set.of(Delete.class,
                           Insert.class,
                           Update.class,
                           Save.class);

    /**
     * Annotations that represent operations that are allowed for methods of a
     * stateful repository.
     */
    private static final Set<Class<? extends Annotation>> OP_ANNOS_STATEFUL = //
                    Set.of(Find.class,
                           Query.class);

    /**
     * Annotations that represent operations that are allowed for methods of a
     * stateless repository.
     */
    private static final Set<Class<? extends Annotation>> OP_ANNOS_STATELESS = //
                    Set.of(Delete.class,
                           Find.class,
                           Insert.class,
                           Query.class,
                           Save.class,
                           Update.class);

    /**
     * Classes that are valid as return types of resource accessor methods for a
     * stateful repository.
     */
    private static final Set<Class<?>> RESOURCE_ACCESSOR_CLASSES_STATEFUL = //
                    Set.of(Connection.class,
                           DataSource.class,
                           EntityManager.class);

    /**
     * Classes that are valid as return types of resource accessor methods for a
     * stateless repository.
     */
    private static final Set<Class<?>> RESOURCE_ACCESSOR_CLASSES_STATELESS = //
                    RESOURCE_ACCESSOR_CLASSES_STATEFUL;

    /**
     * Types that are valid as repository method special parameters.
     */
    private static final Set<Class<?>> SPECIAL_PARAM_TYPES = //
                    Set.of(Limit.class, Order.class, PageRequest.class,
                           Sort.class, Sort[].class);

    @Override
    @Trivial
    public StringBuilder appendCondition(StringBuilder q, int qp,
                                         Method method, int p,
                                         String o_, String attrName,
                                         boolean isCollection, Annotation[] annos) {
        if (attrName.charAt(attrName.length() - 1) != ')')
            q.append(o_);
        return q.append(attrName).append("=?").append(qp);
    }

    @Override
    @Trivial
    public StringBuilder appendConditionsForIdClass(StringBuilder q, int qp,
                                                    Method method, int p,
                                                    String o_, String[] idClassAttrNames,
                                                    Annotation[] annos) {
        q.append('(');

        int count = 0;
        for (String name : idClassAttrNames) {
            if (count != 0)
                q.append(" AND ");

            q.append(o_).append(name).append("=?").append(count++ + qp);
        }

        q.append(')');

        return q;
    }

    @Override
    @Trivial
    public boolean atLeast(int major, int minor) {
        return major == 1 && minor == 0;
    }

    @Override
    @Trivial
    public Annotation getCountAnnotation(Method method) {
        return null;
    }

    @Override
    @Trivial
    public Class<?> getEntityClass(Find find) {
        return void.class;
    }

    @Override
    @Trivial
    public Annotation getExistsAnnotation(Method method) {
        return null;
    }

    @Override
    @Trivial
    public String[] getSelections(AnnotatedElement element) {
        return NO_SELECTIONS;
    }

    @Override
    @Trivial
    public String[] getUpdateAttributeAndOperation(Annotation[] annos) {
        return null; // let the caller raise an appropriate error
    }

    @Override
    @Trivial
    public boolean hasOrAnnotation(Annotation[] annos) {
        return false;
    }

    @Override
    @Trivial
    public Set<Class<? extends Annotation>> lifeCycleAnnoTypes(boolean stateful) {
        return stateful ? LIFECYCLE_ANNOS_STATEFUL : LIFECYCLE_ANNOS_STATELESS;
    }

    @Override
    @Trivial
    public Set<Class<? extends Annotation>> operationAnnoTypes(boolean stateful) {
        return stateful ? OP_ANNOS_STATEFUL : OP_ANNOS_STATELESS;
    }

    @Override
    @Trivial
    public Set<Class<?>> resourceAccessorTypes(boolean stateful) {
        return stateful ? RESOURCE_ACCESSOR_CLASSES_STATEFUL //
                        : RESOURCE_ACCESSOR_CLASSES_STATELESS;
    }

    @Override
    @Trivial
    public String specialParamsForFind() {
        return "Limit, PageRequest, Order, Sort, Sort[]";
    }

    @Override
    @Trivial
    public String specialParamsForFindAndDelete() {
        return "Limit, Order, Sort, Sort[]";
    }

    @Override
    @Trivial
    public Set<Class<?>> specialParamTypes() {
        return SPECIAL_PARAM_TYPES;
    }
}