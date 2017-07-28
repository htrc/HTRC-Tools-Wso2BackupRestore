package org.hathitrust.htrc.wso2.tools.backuprestore;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigException;
import com.typesafe.config.ConfigFactory;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hathitrust.htrc.wso2.tools.backuprestore.exceptions.BackupRestoreException;
import org.hathitrust.htrc.wso2.tools.backuprestore.exceptions.ConfigurationException;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.RegistryUtils;
import org.wso2.carbon.registry.core.config.RegistryContext;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Meta-class for storing required references for performing backups and restores
 *
 * @author capitanu
 */
public class BackupRestore implements ServletContextListener {

    private final Log log = LogFactory.getLog(BackupRestore.class);

    protected RegistryUtils _registryUtils;
    protected RegistryExtensionConfig _config;

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        ServletContext context = servletContextEvent.getServletContext();
        String webappName = context.getServletContextName();

        try {
            // attempt to load the configuration file
            Config config = getConfigProperties(context);
            Config htrcConfig;
            try {
                htrcConfig = config.getConfig(Constants.HTRC_CONFIG_PARAM);
            }
            catch (ConfigException.Missing e) {
                throw new ConfigurationException(
                    "Missing configuration section: " + Constants.HTRC_CONFIG_PARAM);
            }

            RegistryContext registryContext = RegistryContext.getBaseInstance();
            if (registryContext == null) {
                throw new BackupRestoreException(
                    "Could not obtain a RegistryContext instance!");
            }

            RegistryService registryService = registryContext.getEmbeddedRegistryService();
            RealmService realmService = registryContext.getRealmService();

            _config = new RegistryExtensionConfig(htrcConfig);
            _registryUtils = new RegistryUtils(registryService, realmService);

            context.setAttribute(this.getClass().getName(), this);

            log.info(webappName + " successfully initialized");
        }
        catch (Exception e) {
            log.error("Error initializing " + webappName, e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
    }

    /**
     * Load the registry extension configuration
     *
     * @param servletContext The {@link ServletContext} instance
     * @return The {@link Config} instance holding the registry extension configuration
     * @throws IOException Thrown if the configuration file is not found or is invalid
     */
    private Config getConfigProperties(ServletContext servletContext) throws IOException {
        String htrcConfig = servletContext.getInitParameter(Constants.WEBXML_CONFIG_PARAM);
        if (htrcConfig == null) {
            htrcConfig = Constants.DEFAULT_CONFIG_LOCATION;
        }

        URL configUrl = servletContext.getResource(htrcConfig);
        if (configUrl == null) {
            throw new FileNotFoundException("Missing configuration file: " + htrcConfig);
        }

        log.info("Loading WSO2 Backup Restore configuration from " + htrcConfig);

        return ConfigFactory.parseURL(configUrl).resolve();
    }

    /**
     * Return the {@link RegistryUtils} instance used to access helper Registry functionality
     *
     * @return The {@link RegistryUtils} instance
     */
    public RegistryUtils getRegistryUtils() {
        return _registryUtils;
    }

    /**
     * Return the {@link RegistryExtensionConfig} instance used to access the Registry Extension
     * configuration settings
     *
     * @return The {@link RegistryExtensionConfig} instance
     */
    public RegistryExtensionConfig getConfig() {
        return _config;
    }
}
