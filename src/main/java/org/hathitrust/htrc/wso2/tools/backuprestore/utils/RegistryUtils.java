package org.hathitrust.htrc.wso2.tools.backuprestore.utils;

import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.AuthorizationManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Registry utility helper methods
 *
 * @author capitanu
 */
public class RegistryUtils {

    private final RegistryService _registryService;
    private final int _tenantId;
    private final String _adminUser;
    private final String _adminRole;
    private final String _everyoneRole;

    /**
     * Constructor
     *
     * @param registryService The {@link RegistryService} instance
     * @param realmService    The {@link RealmService} instance
     */
    public RegistryUtils(RegistryService registryService, RealmService realmService) {
        _registryService = registryService;

        RealmConfiguration bootstrapConfig = realmService.getBootstrapRealmConfiguration();
        _tenantId = bootstrapConfig.getTenantId();
        _adminUser = bootstrapConfig.getAdminUserName();
        _adminRole = bootstrapConfig.getAdminRoleName();
        _everyoneRole = bootstrapConfig.getEveryOneRoleName();
    }

    /**
     * Get a chrooted registry instance
     *
     * @param userName The user name
     * @param chroot   The root path
     * @return The {@link UserRegistry} instance
     * @throws RegistryException Thrown if a registry error occurs
     */
    public UserRegistry getChrootUserRegistry(String userName, String chroot)
        throws RegistryException {
        return _registryService.getRegistry(userName, _tenantId, chroot);
    }

    /**
     * Get a registry instance for the admin user
     *
     * @return The {@link UserRegistry} instance
     * @throws RegistryException Thrown if a registry error occurs
     */
    public UserRegistry getAdminRegistry() throws RegistryException {
        return getUserRegistry(_adminUser);
    }

    /**
     * Get a registry instance for a user
     *
     * @param userName The user name
     * @return The {@link UserRegistry} instance
     * @throws RegistryException Thrown if a registry error occurs
     */
    public UserRegistry getUserRegistry(String userName) throws RegistryException {
        return _registryService.getRegistry(userName, _tenantId);
    }

    /**
     * Authorize access to a resource for all users
     *
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to authorize
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public void authorizeEveryone(String resPath, UserRegistry registry,
                                  String... permissions)
        throws RegistryException, UserStoreException {
        authorizeRole(_everyoneRole, resPath, registry, permissions);
    }

    /**
     * Authorize access to a resource for particular role
     *
     * @param roleName    The role
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to authorize
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public void authorizeRole(String roleName, String resPath, UserRegistry registry,
                              String... permissions) throws RegistryException, UserStoreException {
        UserRealm userRealm = registry.getUserRealm();
        AuthorizationManager authManager = userRealm.getAuthorizationManager();

        for (String permission : permissions) {
            authManager.authorizeRole(roleName, resPath, permission);
        }
    }

    /**
     * Deny access to a resource for all users
     *
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to deny
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public void denyEveryone(String resPath, UserRegistry registry, String... permissions)
        throws RegistryException, UserStoreException {
        denyRole(_everyoneRole, resPath, registry, permissions);
    }

    /**
     * Deny access to a resource for a particular role
     *
     * @param roleName    The role
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to deny
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public void denyRole(String roleName, String resPath, UserRegistry registry,
                         String... permissions) throws RegistryException, UserStoreException {
        UserRealm userRealm = registry.getUserRealm();
        AuthorizationManager authManager = userRealm.getAuthorizationManager();

        for (String permission : permissions) {
            authManager.denyRole(roleName, resPath, permission);
        }
    }

    /**
     * Clear public permissions to a resource (set permissions as inherited from parent)
     *
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to clear
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public void clearEveryone(String resPath, UserRegistry registry, String... permissions)
        throws RegistryException, UserStoreException {
        clearRole(_everyoneRole, resPath, registry, permissions);
    }

    /**
     * Clear role permissions to a resource (set permissions as inherited from parent)
     *
     * @param roleName    The role
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to clear
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public void clearRole(String roleName, String resPath, UserRegistry registry,
                          String... permissions) throws RegistryException, UserStoreException {
        UserRealm userRealm = registry.getUserRealm();
        AuthorizationManager authManager = userRealm.getAuthorizationManager();

        for (String permission : permissions) {
            authManager.clearRoleAuthorization(roleName, resPath, permission);
        }
    }

    /**
     * Checks whether the resource has the specified public permissions
     *
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to check
     * @return True if the resource has the specified public permissions, False otherwise
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public boolean isEveryoneAuthorized(String resPath, UserRegistry registry,
                                        String... permissions)
        throws RegistryException, UserStoreException {
        UserRealm userRealm = registry.getUserRealm();
        AuthorizationManager authManager = userRealm.getAuthorizationManager();

        for (String permission : permissions) {
            if (!authManager.isRoleAuthorized(_everyoneRole, resPath, permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verify whether access is granted to a registry resource for the given permissions
     *
     * @param resPath     The resource path
     * @param registry    The {@link UserRegistry} instance
     * @param permissions The permissions to check
     * @return True if authorized, False otherwise
     * @throws RegistryException  Thrown if a registry error occurs
     * @throws UserStoreException Thrown if a user store error occurs
     */
    public boolean isAuthorized(String resPath, UserRegistry registry, String... permissions)
        throws RegistryException, UserStoreException {
        UserRealm userRealm = registry.getUserRealm();
        AuthorizationManager authManager = userRealm.getAuthorizationManager();

        for (String permission : permissions) {
            if (!authManager.isRoleAuthorized(registry.getUserName(), resPath, permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Retrieves the admin user name
     *
     * @return The admin user name
     */
    public String getAdminUser() { return _adminUser; }

    /**
     * Retrieves the admin role name
     *
     * @return The admin role name
     */
    public String getAdminRole() {
        return _adminRole;
    }

    /**
     * Retrieves the "everyone" role name
     *
     * @return The "everyone" role name
     */
    public String getEveryoneRole() {
        return _everyoneRole;
    }

    /**
     * Retrieves the current tenant id
     *
     * @return The current tenant id
     */
    public int getTenantId() {
        return _tenantId;
    }
}
