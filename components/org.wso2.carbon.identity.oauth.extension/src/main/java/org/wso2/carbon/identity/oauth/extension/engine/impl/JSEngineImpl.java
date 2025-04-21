/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.engine.impl;

import jdk.nashorn.api.scripting.ClassFilter;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;
import jdk.nashorn.api.scripting.ScriptObjectMirror;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.script.Bindings;
import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

/**
 * This class is used to evaluate the javascripts.
 */
public class JSEngineImpl implements JSEngine {

    private ClassFilter classFilter;
    private final ScriptEngine engine;
    private static final String[] NASHORN_ARGS = {"--no-java", "--no-deprecation-warning"};
    private static final String REMOVE_FUNCTIONS = "var quit=function(){Log.error('quit function is restricted.')};" +
            "var exit=function(){Log.error('exit function is restricted.')};" +
            "var print=function(){Log.error('print function is restricted.')};" +
            "var echo=function(){Log.error('echo function is restricted.')};" +
            "var readFully=function(){Log.error('readFully function is restricted.')};" +
            "var readLine=function(){Log.error('readLine function is restricted.')};" +
            "var load=function(){Log.error('load function is restricted.')};" +
            "var loadWithNewGlobal=function(){Log.error('loadWithNewGlobal function is restricted.')};" +
            "var $ARG=null;var $ENV=null;var $EXEC=null;" +
            "var $OPTIONS=null;var $OUT=null;var $ERR=null;var $EXIT=null;" +
            "Object.defineProperty(this, 'engine', {});";
    private static final JSEngine JS_ENGINE_INSTANCE = new JSEngineImpl();
    private static final Logger log = LogManager.getLogger(JSEngineImpl.class);

    public JSEngineImpl() {

        log.debug("Initializing JSEngineImpl with JDK Nashorn engine and security restrictions");
        NashornScriptEngineFactory factory = new NashornScriptEngineFactory();
        classFilter = new RestrictedClassFilter();
        this.engine = factory.getScriptEngine(NASHORN_ARGS, getClassLoader(), classFilter);
        if (this.engine != null) {
            log.debug("JSEngineImpl successfully initialized with JDK Nashorn engine and security restrictions");
        } else {
            log.error("Failed to initialize JDK Nashorn engine - engine instance is null");
        }
    }

    /**
     * Returns an instance to log the javascript errors.
     *
     * @return jsBasedEngineInstance instance.
     */
    public static JSEngine getInstance() {
        
        log.debug("Returning JSEngineImpl singleton instance");
        return JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine createEngine() throws ScriptException {

        log.debug("Creating new JDK Nashorn JS engine instance with security restrictions");
        try {
            Bindings bindings = engine.createBindings();
            engine.setBindings(bindings, ScriptContext.GLOBAL_SCOPE);
            engine.setBindings(engine.createBindings(), ScriptContext.ENGINE_SCOPE);
            engine.eval(REMOVE_FUNCTIONS);
            log.info("Successfully created JDK Nashorn JS engine with security restrictions applied");
            return JS_ENGINE_INSTANCE;
        } catch (ScriptException e) {
            log.error("Error creating JDK Nashorn JS engine instance: {}. Script evaluation failed while applying security restrictions", 
                    e.getMessage());
            log.debug("JDK Nashorn JS engine creation failed with exception", e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error creating JDK Nashorn JS engine instance: {}", e.getMessage());
            log.debug("Unexpected exception during JDK Nashorn JS engine creation", e);
            throw new ScriptException(e);
        }
    }

    @Override
    public JSEngine addBindings(Map<String, Object> bindings) {

        if (bindings == null || bindings.isEmpty()) {
            log.debug("No bindings to add to JS engine");
            return JS_ENGINE_INSTANCE;
        }
        
        log.debug("Adding {} bindings to JS engine", bindings.size());
        engine.getBindings(ScriptContext.ENGINE_SCOPE).putAll(bindings);
        return JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine evalScript(String script) throws ScriptException {

        if (script == null || script.isEmpty()) {
            log.warn("Attempted to evaluate empty script");
            return JS_ENGINE_INSTANCE;
        }
        
        log.debug("Evaluating JavaScript script");
        try {
            engine.eval(script, engine.getBindings(ScriptContext.ENGINE_SCOPE));
            log.debug("Script evaluation completed successfully");
            return JS_ENGINE_INSTANCE;
        } catch (ScriptException e) {
            log.error("Error evaluating JavaScript script: {}", e.getMessage());
            throw e;
        }
    }

    @Override
    public JSEngine invokeFunction(String functionName, Object... args) throws NoSuchMethodException, ScriptException {

        if (functionName == null || functionName.isEmpty()) {
            log.warn("Attempted to invoke function with empty name");
            return JS_ENGINE_INSTANCE;
        }
        
        log.debug("Attempting to invoke JavaScript function: {}", functionName);
        Object scriptObj = engine.get(functionName);
        if (scriptObj != null && ((ScriptObjectMirror) scriptObj).isFunction()) {
            try {
                Invocable invocable = (Invocable) engine;
                invocable.invokeFunction(functionName, args);
                log.debug("Successfully invoked function: {}", functionName);
                return JS_ENGINE_INSTANCE;
            } catch (ScriptException e) {
                log.error("Error invoking JavaScript function {}: {}", functionName, e.getMessage());
                throw e;
            } catch (NoSuchMethodException e) {
                log.error("Function {} not found in script context", functionName);
                throw e;
            }
        }
        log.warn("Function {} is not defined in the script", functionName);
        return JS_ENGINE_INSTANCE;
    }

    @Override
    public Map<String, Object> getJSObjects(List<String> objectNames) {

        if (objectNames == null || objectNames.isEmpty()) {
            log.debug("Empty list of object names provided to getJSObjects");
            return new HashMap<>();
        }
        
        log.debug("Retrieving {} JavaScript objects from engine context", objectNames.size());
        Map<String, Object> jsObjects = new HashMap<>();
        for (String objectName : objectNames) {
            if (objectName != null) {
                Object jsObject = engine.get(objectName);
                if (jsObject != null) {
                    jsObjects.put(objectName, jsObject);
                    log.debug("Retrieved JavaScript object: {}", objectName);
                } else {
                    log.debug("JavaScript object not found: {}", objectName);
                }
            }
        }
        
        log.debug("Retrieved {} JavaScript objects out of {} requested", jsObjects.size(), objectNames.size());
        return jsObjects;
    }

    /**
     * This method returns the current thread's class loader.
     * @return Returns NashornScriptEngineFactory class to evaluate the javascript if classLoader is null.
     */
    private ClassLoader getClassLoader() {

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            log.debug("Thread context class loader is null, using NashornScriptEngineFactory class loader");
            return NashornScriptEngineFactory.class.getClassLoader();
        } else {
            log.debug("Using thread context class loader");
            return classLoader;
        }
    }

    /**
     * This is used by the Nashorn engine to determine which Java classes should be exposed to JavaScript code. In this
     * implementation, the exposeToScripts() method always returns false, which means that no classes will be exposed
     * to JavaScript code. Use for security purposes.
     */
    private static class RestrictedClassFilter implements ClassFilter {
        private static final Logger filterLog = LogManager.getLogger(RestrictedClassFilter.class);

        @Override
        public boolean exposeToScripts(String className) {
            if (filterLog.isDebugEnabled()) {
                filterLog.debug("JDK Nashorn security - blocking attempted access to Java class: {}", className);
            }
            return false;
        }
    }
}
