package org.hathitrust.htrc.wso2.tools.backuprestore;

import com.typesafe.config.Config;
import java.util.Arrays;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hathitrust.htrc.wso2.tools.backuprestore.exceptions.ConfigurationException;

/**
 * Class to hold the Registry Extension configuration settings
 *
 * @author capitanu
 */
public class RegistryExtensionConfig {

    /**
     * The array of required config parameters
     */
    public static final String[] REQUIRED_CONFIG_PARAMS = new String[] {
        Constants.HTRC_CONFIG_BASE_PATH,
        Constants.HTRC_CONFIG_PUBLIC_HOME,
        Constants.HTRC_CONFIG_PUBLIC_FILES,
        Constants.HTRC_CONFIG_USER_WORKSETS,
        Constants.HTRC_CONFIG_USER_FILES,
        Constants.HTRC_CONFIG_USER_JOBS
    };
    private static final Log Log = LogFactory.getLog(RegistryExtensionConfig.class);
    private final String _cfgBasePath;
    private final String _cfgPublicFilesPath;
    private final String _cfgPublicPath;
    private final String _cfgUserWorksetsPath;
    private final String _cfgUserFilesPath;
    private final String _cfgUserHomePath;
    private final String _cfgUserJobsPath;

    /**
     * Constructor
     *
     * @param config The registry extension configuration properties
     * @throws ConfigurationException Thrown if incomplete configuration
     */
    public RegistryExtensionConfig(Config config) throws ConfigurationException {
        // check for existence of required config parameters
        for (String cfgParam : REQUIRED_CONFIG_PARAMS) {
            if (!config.hasPath(cfgParam)) {
                throw new ConfigurationException(
                    "Incomplete configuration - required parameters: " + Arrays
                        .toString(REQUIRED_CONFIG_PARAMS));
            }
        }

        if (config.hasPath(Constants.HTRC_CONFIG_DEBUG) &&
            config.getBoolean(Constants.HTRC_CONFIG_DEBUG)) {
            Log.info("== Configuration ==");
            for (String cfgParam : REQUIRED_CONFIG_PARAMS) {
                Log.info(
                    "== " + cfgParam + ": " + config.getValue(cfgParam).unwrapped().toString());
            }
        }

        _cfgBasePath = config.getString(Constants.HTRC_CONFIG_BASE_PATH);
        _cfgPublicPath = config.getString(Constants.HTRC_CONFIG_PUBLIC_HOME);
        _cfgPublicFilesPath = config.getString(Constants.HTRC_CONFIG_PUBLIC_FILES);
        _cfgUserWorksetsPath = config.getString(Constants.HTRC_CONFIG_USER_WORKSETS);
        _cfgUserFilesPath = config.getString(Constants.HTRC_CONFIG_USER_FILES);
        _cfgUserHomePath = config.getString(Constants.HTRC_CONFIG_USER_HOME);
        _cfgUserJobsPath = config.getString(Constants.HTRC_CONFIG_USER_JOBS);
    }

    /**
     * Return the base path of where the registry extension stores artifacts in the registry
     *
     * @return The base path of where the registry extension stores artifacts in the registry
     */
    public String getBasePath() {
        return _cfgBasePath;
    }

    /**
     * Return the base path of where public artifacts are stored in the registry
     *
     * @return The base path of where public artifacts are stored in the registry
     */
    public String getPublicPath() {
        return _cfgPublicPath;
    }

    /**
     * Return the path where public (shared) files are stored in the registry
     *
     * @return The path where public (shared) files are stored in the registry
     */
    public String getPublicFilesPath() {
        return _cfgPublicFilesPath;
    }

    /**
     * Return the location where user files are stored in the registry
     *
     * @param userName The user name
     * @return The location where user files are stored in the registry
     */
    public String getUserFilesPath(String userName) {
        return String.format(_cfgUserFilesPath, userName);
    }

    /**
     * Return the registry path for the given workset, for the given user
     *
     * @param worksetId The workset id (name)
     * @param userName  The user name
     * @return The registry path for the given workset, for the given user
     */
    public String getWorksetPath(String worksetId, String userName) {
        return getUserWorksetsPath(userName) + "/" + worksetId;
    }

    /**
     * Return the location where user worksets are stored in the registry
     *
     * @param userName The user name
     * @return The location where user worksets are stored in the registry
     */
    public String getUserWorksetsPath(String userName) {
        return String.format(_cfgUserWorksetsPath, userName);
    }

    /**
     * Return the user's home path
     *
     * @param userName The user name
     * @return The registry path for the user's home
     */
    public String getUserHomePath(String userName) {
        return String.format(_cfgUserHomePath, userName);
    }

    /**
     * Return the user's jobs path
     *
     * @param userName The user name
     * @return The registry path for the user's jobs
     */
    public String getUserJobsPath(String userName) {
        return String.format(_cfgUserJobsPath, userName);
    }
}
