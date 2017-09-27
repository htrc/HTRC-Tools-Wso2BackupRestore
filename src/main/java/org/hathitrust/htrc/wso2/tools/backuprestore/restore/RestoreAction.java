package org.hathitrust.htrc.wso2.tools.backuprestore.restore;

import edu.illinois.i3.htrc.registry.entities.backup.Backup;
import edu.illinois.i3.htrc.registry.entities.backup.BackupMeta;
import edu.illinois.i3.htrc.registry.entities.backup.RegFile;
import edu.illinois.i3.htrc.registry.entities.backup.ResProperty;
import edu.illinois.i3.htrc.registry.entities.backup.UserFiles;
import edu.illinois.i3.htrc.registry.entities.security.Claim;
import edu.illinois.i3.htrc.registry.entities.security.Role;
import edu.illinois.i3.htrc.registry.entities.security.User;
import edu.illinois.i3.htrc.registry.entities.workset.Volume;
import edu.illinois.i3.htrc.registry.entities.workset.Volumes;
import edu.illinois.i3.htrc.registry.entities.workset.Workset;
import edu.illinois.i3.htrc.registry.entities.workset.WorksetContent;
import edu.illinois.i3.htrc.registry.entities.workset.WorksetMeta;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.hathitrust.htrc.wso2.tools.backuprestore.BackupRestore;
import org.hathitrust.htrc.wso2.tools.backuprestore.Constants;
import org.hathitrust.htrc.wso2.tools.backuprestore.HTRCMediaTypes;
import org.hathitrust.htrc.wso2.tools.backuprestore.RegistryExtensionConfig;
import org.hathitrust.htrc.wso2.tools.backuprestore.exceptions.BackupRestoreException;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.RegistryUtils;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.Wso2Utils;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.config.RegistryContext;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.dataaccess.JDBCDataAccessManager;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.registry.core.utils.AccessControlConstants;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.AuthorizationManager;
import org.wso2.carbon.user.core.Permission;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.system.SystemUserRoleManager;
import org.wso2.carbon.user.mgt.UserMgtConstants;
import org.wso2.carbon.user.mgt.UserRealmProxy;
import org.wso2.carbon.user.mgt.common.UserAdminException;

/**
 * Defines how restores are performed
 *
 * @author capitanu
 */
public class RestoreAction {

    protected static final Pattern VALID_HTRC_ID_REGEX = Pattern.compile("^\\w{2,4}\\.\\S{4,30}$");
    private static final String SET_RES_META_SQL = "UPDATE REG_PATH rp JOIN REG_RESOURCE rr USING (REG_PATH_ID) SET rr.REG_CREATOR = ?, rr.REG_CREATED_TIME = ?, rr.REG_LAST_UPDATOR = ?, rr.REG_LAST_UPDATED_TIME = ? WHERE CONCAT(rp.REG_PATH_VALUE, '/', rr.REG_NAME) = ?";
    private static final String SET_COLL_META_SQL = "UPDATE REG_PATH rp JOIN REG_RESOURCE rr USING (REG_PATH_ID) SET rr.REG_CREATOR = ?, rr.REG_CREATED_TIME = ?, rr.REG_LAST_UPDATOR = ?, rr.REG_LAST_UPDATED_TIME = ? WHERE rp.REG_PATH_VALUE = ? AND rr.REG_NAME IS NULL";
    private final PrintWriter progressWriter;
    private final RegistryUtils registryUtils;
    private final RegistryExtensionConfig config;
    private final UserRegistry adminRegistry;
    private final UserStoreManager userStoreManager;
    private final AuthorizationManager authorizationManager;
    private final UserRealmProxy userRealmProxy;
    private final DataSource dataSource;
    private final JAXBContext jaxbVolumesContext;
    private final SystemUserRoleManager systemUserRoleManager;
    private int numFilesRestored;
    private int numMalformedWorksets;

    /**
     * Restore constructor
     *
     * @param backupRestore  Instance holding configuration and other useful references
     * @param progressWriter The writer where progress information is written to
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    public RestoreAction(BackupRestore backupRestore, PrintWriter progressWriter)
        throws BackupRestoreException {
        this.progressWriter = progressWriter;
        this.registryUtils = backupRestore.getRegistryUtils();
        this.config = backupRestore.getConfig();
        RegistryContext registryContext = RegistryContext.getBaseInstance();
        this.dataSource = ((JDBCDataAccessManager) registryContext
            .getDataAccessManager()).getDataSource();
        int tenantId = registryUtils.getTenantId();

        try {
            this.adminRegistry = registryUtils.getAdminRegistry();
            UserRealm userRealm = adminRegistry.getUserRealm();
            this.userRealmProxy = new UserRealmProxy(userRealm);
            this.userStoreManager = userRealm.getUserStoreManager();
            this.systemUserRoleManager = new SystemUserRoleManager(dataSource, tenantId);
            this.authorizationManager = userRealm.getAuthorizationManager();
            this.jaxbVolumesContext = JAXBContext.newInstance(Volumes.class, Volume.class);
        }
        catch (org.wso2.carbon.user.core.UserStoreException | RegistryException | JAXBException e) {
            throw new BackupRestoreException("Could not initialize the restore function", e);
        }
    }

    /**
     * Performs the restore
     *
     * @param backupDir The directory containing the backup data
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    public void restore(File backupDir) throws BackupRestoreException {
        File filesDir = new File(backupDir, "files");
        if (!filesDir.exists()) {
            throw new BackupRestoreException("Invalid backup directory (missing files dir)");
        }

        numFilesRestored = 0;
        numMalformedWorksets = 0;

        log("Loading backup file...");
        Backup backup = readBackup(backupDir);

        BackupMeta backupMeta = backup.getMetadata();
        log("Backup created on %s loaded...", backupMeta.getCreatedAt().getTime());

        if (!Constants.BACKUP_VERSION.equalsIgnoreCase(backupMeta.getVersion())) {
            throw new BackupRestoreException(
                String.format("Incompatible backup version! Found: %s  Required: %s",
                              backupMeta.getVersion(), Constants.BACKUP_VERSION
                )
            );
        }

        Map<String, String> roleMap = new HashMap<>();
        roleMap.put(backupMeta.getAdminRoleName().toLowerCase(), registryUtils.getAdminRole());
        roleMap.put(
            backupMeta.getEveryoneRole().getName().toLowerCase(),
            registryUtils.getEveryoneRole()
        );
        roleMap.put("everyone", registryUtils.getEveryoneRole()); // needed to fix old WSO2 data

        setEveryoneRolePermissions(backupMeta.getEveryoneRole());

        ///////////////////
        // Sanity checks
        ///////////////////

        log("Performing sanity checks:");
        Set<String> allRoleNames = new HashSet<>();
        for (Role role : backup.getRoles())
            allRoleNames.add(role.getName().toLowerCase());

        Set<String> allUserNames = new HashSet<>();
        for (User user : backup.getUsers())
            allUserNames.add(user.getName().toLowerCase());

        Set<String> usersWithData = new HashSet<>();
        for (Workset workset : backup.getWorksets())
            usersWithData.add(workset.getMetadata().getAuthor().toLowerCase());
        for (UserFiles userFiles : backup.getUserFilespace())
            usersWithData.add(userFiles.getUser().toLowerCase());

        // - check that for every role there is a username associated
        log("Checking that for every role there is an associated username...");
        Set<String> orphanRoles = new HashSet<>(allRoleNames);
        orphanRoles.removeAll(allUserNames);
        if (!orphanRoles.isEmpty()) {
            for (String roleName : orphanRoles)
                log("WARN: orphan role: %s", roleName);
        }

        // - check that for every username there is a role associated
        log("Checking that for every username there is an associated role...");
        Set<String> orphanUsers = new HashSet<>(allUserNames);
        orphanUsers.removeAll(allRoleNames);
        if (!orphanUsers.isEmpty()) {
            for (String userName : orphanUsers)
                log("WARN: orphan user: %s", userName);
        }

        // - check that all users that own either files or worksets exist
        Set<String> invalidUsersWithData = new HashSet<>(usersWithData);
        invalidUsersWithData.removeAll(allUserNames);
        if (!invalidUsersWithData.isEmpty()) {
            for (String userName : invalidUsersWithData)
                log("WARN: orphaned user with data: %s", userName);
        }

        // End sanity checks

        Set<String> skipUsers = new HashSet<>(invalidUsersWithData);

        Set<String> reservedRoleNames = getReservedRoleNames();
        for (Role role : backup.getRoles()) {
            String roleName = role.getName().toLowerCase();
//            if (orphanRoles.contains(roleName)) {
//                log("Skipping orphaned role '%s'...", roleName);
//                continue;
//            }
            if (reservedRoleNames.contains(roleName)) {
                log("CONFLICT! Cannot restore reserved role name: %s", roleName);
                continue;
            }
            log("Creating role '%s'...", roleName);
            createRole(role);
        }

        Set<String> reservedUserNames = getReservedUserNames();
        for (User user : backup.getUsers()) {
            String userName = user.getName().toLowerCase();
//            if (orphanUsers.contains(userName)) {
//                log("Skipping orphaned user '%s'...", userName);
//                continue;
//            }
            if (reservedUserNames.contains(userName)) {
                log("CONFLICT! Cannot restore reserved user name: %s", userName);
                continue;
            }
            log("Creating user '%s'...", userName);
            try {
                createUser(user);
            }
            catch (BackupRestoreException e) {
                log("Cannot create user '%s': %s", userName, e.getMessage());
                skipUsers.add(userName);
            }
        }

        for (UserFiles userFiles : backup.getUserFilespace()) {
            String userName = userFiles.getUser().toLowerCase();
            if (skipUsers.contains(userName)) {
                log("WARN: Skipping restore of files for user %s", userName);
                continue;
            }
            log("Restoring files for user %s...", userName);
            String regUserFiles = config.getUserFilesPath(userName);
            restoreFiles(userFiles.getRegFiles(), regUserFiles, filesDir, roleMap);
        }

        log("Creating public filespace...");
        createPublicFilespace();

        log("Restoring public files...");
        String regPublicFiles = config.getPublicFilesPath();
        restoreFiles(backup.getPublicFilespace().getRegFiles(), regPublicFiles, filesDir, roleMap);

        for (Workset workset : backup.getWorksets()) {
            WorksetMeta worksetMeta = workset.getMetadata();
            String worksetName = worksetMeta.getName();
            String worksetOwner = worksetMeta.getAuthor().toLowerCase();
            if (skipUsers.contains(worksetOwner)) {
                log("WARN: Skipping restore of workset '%s' for user %s!", worksetName, worksetOwner);
                continue;
            }
            log("Restoring workset '%s' of user '%s'", worksetName, worksetOwner);
            restoreWorkset(workset);
        }

        log("All done! Restored %,d roles, %,d users, %,d files, and %,d worksets "
                + "(of which %,d were tagged as malformed)", backup.getRoles().size(),
            backup.getUsers().size(), numFilesRestored, backup.getWorksets().size(),
            numMalformedWorksets
        );
    }

    /**
     * Creates the home space of a user
     *
     * @param userName The user name
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void createUserHome(String userName) throws BackupRestoreException {
        try {
            String regUserHome = config.getUserHomePath(userName);
            String regUserFiles = config.getUserFilesPath(userName);
            String regUserWorksets = config.getUserWorksetsPath(userName);
            String regUserJobs = config.getUserJobsPath(userName);

            Collection userHomeCollection = adminRegistry.newCollection();
            regUserHome = adminRegistry.put(regUserHome, userHomeCollection);

            String homePermissions = String
                .format("%s:GDPA|%s:gdpa", userName, registryUtils.getEveryoneRole());
            setResourceRolePermissions(regUserHome, homePermissions, null);

            Collection filesCollection = adminRegistry.newCollection();
            String extra = userName.endsWith("s") ? "'" : "'s";
            filesCollection.setDescription(userName + extra + " file space");
            regUserFiles = adminRegistry.put(regUserFiles, filesCollection);

            Collection worksetsCollection = adminRegistry.newCollection();
            worksetsCollection.setDescription(userName + extra + " worksets");
            regUserWorksets = adminRegistry.put(regUserWorksets, worksetsCollection);

            Collection jobsCollection = adminRegistry.newCollection();
            jobsCollection.setDescription(userName + extra + " jobs");
            regUserJobs = adminRegistry.put(regUserJobs, jobsCollection);
        }
        catch (RegistryException e) {
            log("Error while creating home collection for user '%s' (Cause: %s)",
                userName, e.getMessage()
            );
        }
    }

    /**
     * Retrieves the list of reserved user names
     *
     * @return The list of reserved user names
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected Set<String> getReservedUserNames() throws BackupRestoreException {
        try {
            Set<String> reservedUserNames = new HashSet<>();
            reservedUserNames.add(registryUtils.getAdminUser().toLowerCase());
            reservedUserNames.add("wso2.anonymous.user");
            reservedUserNames.addAll(Arrays.asList(systemUserRoleManager.getSystemUsers()));

            return reservedUserNames;
        }
        catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new BackupRestoreException("Cannot retrieve list of reserved user names", e);
        }
    }

    /**
     * Retrieves the list of reserved role names
     *
     * @return The list of reserved role names
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected Set<String> getReservedRoleNames() throws BackupRestoreException {
        try {
            Set<String> reservedRoleNames = new HashSet<>();
            reservedRoleNames.add(registryUtils.getAdminRole().toLowerCase());
            reservedRoleNames.add(registryUtils.getEveryoneRole().toLowerCase());
            reservedRoleNames.add("wso2.anonymous.role");
            reservedRoleNames.addAll(Arrays.asList(systemUserRoleManager.getSystemRoles()));

            return reservedRoleNames;
        }
        catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new BackupRestoreException("Cannot retrieve list of reserved role names", e);
        }
    }

    /**
     * Logs a message to the progress log
     *
     * @param format  The message format
     * @param objects The optional message context
     */
    protected void log(String format, Object... objects) {
        String s = String.format(format, objects);
        progressWriter.println(s);
        progressWriter.flush();
    }

    /**
     * Reads and parses the backup data from disk
     *
     * @param backupDir The directory storing the backup data
     * @return The parsed `Backup` instance
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected Backup readBackup(File backupDir) throws BackupRestoreException {
        try {
            JAXBContext context = JAXBContext.newInstance(Backup.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            Backup backup;

            try (Reader reader = new FileReader(new File(backupDir, "backup.xml"))) {
                backup = (Backup) unmarshaller.unmarshal(reader);
            }

            return backup;
        }
        catch (JAXBException | IOException e) {
            throw new BackupRestoreException("Unable to parse backup file", e);
        }
    }

    /**
     * Set permissions for the "everyone" role
     *
     * @param backupEveryoneRole The permissions from the backup
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void setEveryoneRolePermissions(Role backupEveryoneRole)
        throws BackupRestoreException {
        String everyoneRoleName = registryUtils.getEveryoneRole();
        try {
            String[] permissions = backupEveryoneRole.getPermissions().toArray(new String[0]);
            userRealmProxy.setRoleUIPermission(everyoneRoleName, permissions);
        }
        catch (UserAdminException e) {
            throw new BackupRestoreException("Error setting role permissions for role: "
                                                 + everyoneRoleName);
        }
    }

    /**
     * Creates a WSO2 role
     *
     * @param role The role
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void createRole(Role role) throws BackupRestoreException {
        String roleName = role.getName().toLowerCase();

        try {
            List<String> rolePermissions = role.getPermissions();
            Permission[] permissions = new Permission[rolePermissions.size()];
            for (int i = 0, iMax = rolePermissions.size(); i < iMax; i++) {
                String permission = rolePermissions.get(i);
                permissions[i] = new Permission(permission, UserMgtConstants.EXECUTE_ACTION);
            }

            userStoreManager.addRole(roleName, null, permissions);
        }
        catch (UserStoreException e) {
            throw new BackupRestoreException("Unable to create role: " + roleName, e);
        }
    }

    /**
     * Creates a WSO2 user
     *
     * @param user The user
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void createUser(User user) throws BackupRestoreException {
        String userName = user.getName().toLowerCase();

        try {
            Map<String, String> userClaims = new HashMap<>();
            for (Claim claim : user.getClaims()) {
                if (!claim.getUri().startsWith("http://wso2.org/claims/")) { continue; }

                userClaims.put(claim.getUri(), claim.getValue());
            }

            String password = userName + "54321";
            String[] userRole = {userName};

            userStoreManager.addUser(userName, password, userRole, userClaims, "default");

            if (user.isHasHome()) {
                // need to have roles created before a user home can be created
                createUserHome(userName);
            }
        }
        catch (org.wso2.carbon.user.core.UserStoreException e) {
            //log("Error while creating user: '%s' (Cause: %s)\n", user.getName(), e.getMessage());
            throw new BackupRestoreException("Unable to create user: " + userName, e);
        }
    }

    /**
     * Sets the role permissions for a registry resource
     *
     * @param resPath     The resource path
     * @param permissions The (encoded) permissions to set
     * @param roleMap     The optional mapping from external role names to local role names (can be null)
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void setResourceRolePermissions(String resPath, String permissions,
                                              Map<String, String> roleMap)
        throws BackupRestoreException {
        try {
            Resource resource = adminRegistry.get(resPath);
            String resId = resource.getId();
            String roleSep = Pattern.quote("|");

            String[] rolesPermissions = permissions.split(roleSep);

            for (String rolePermissions : rolesPermissions) {
                String[] parts = rolePermissions.split(":");
                String roleName = parts[0];
                if (roleMap != null && roleMap.containsKey(roleName.toLowerCase())) {
                    roleName = roleMap.get(roleName.toLowerCase());
                }
                String perms = parts[1];

                for (char c : perms.toCharArray()) {
                    switch (c) {
                        case 'G':
                            authorizationManager
                                .authorizeRole(roleName, resId, ActionConstants.GET);
                            break;

                        case 'D':
                            authorizationManager
                                .authorizeRole(roleName, resId, ActionConstants.DELETE);
                            break;

                        case 'P':
                            authorizationManager
                                .authorizeRole(roleName, resId, ActionConstants.PUT);
                            break;

                        case 'A':
                            authorizationManager
                                .authorizeRole(roleName, resId, AccessControlConstants.AUTHORIZE);
                            break;

                        case 'g':
                            authorizationManager.denyRole(roleName, resId, ActionConstants.GET);
                            break;

                        case 'd':
                            authorizationManager.denyRole(roleName, resId, ActionConstants.DELETE);
                            break;

                        case 'p':
                            authorizationManager.denyRole(roleName, resId, ActionConstants.PUT);
                            break;

                        case 'a':
                            authorizationManager
                                .denyRole(roleName, resId, AccessControlConstants.AUTHORIZE);
                            break;

                        default:
                            throw new BackupRestoreException("Invalid permission: " + c);
                    }
                }
            }
        }
        catch (org.wso2.carbon.user.core.UserStoreException | RegistryException e) {
            throw new BackupRestoreException("Error setting permissions for: " + resPath, e);
        }
    }

    /**
     * Restores a set of files
     *
     * @param files    The file references to restore
     * @param rootPath The relative path to restore against
     * @param filesDir The location of the file backup data on disk
     * @param roleMap  The optional mapping from external role names to local role names (can be null)
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void restoreFiles(List<RegFile> files, String rootPath, File filesDir,
                                Map<String, String> roleMap)
        throws BackupRestoreException {
        try {
            for (RegFile file : files) {
                String fullPath = rootPath + file.getParentPath() + file.getName();
                String owner = file.getAuthor();

                Properties fileProps = new Properties();
                for (ResProperty p : file.getProperties()) {
                    fileProps.setProperty(p.getKey(), p.getValue());
                }

                if (Boolean.parseBoolean(fileProps.getProperty("registry.link"))) {
                    String targetPath = fileProps.getProperty("registry.actualpath");
                    assert targetPath != null;
                    UserRegistry userRegistry = registryUtils.getUserRegistry(owner);
                    userRegistry.createLink(fullPath, targetPath);
                    if (file.getContentType().equals("collection")) {
                        setCollectionMetadata(fullPath,
                                              owner, file.getCreatedTime().getTime(),
                                              file.getLastModifiedBy(),
                                              file.getLastModified().getTime()
                        );
                    }
                    else {
                        setResourceMetadata(fullPath,
                                            owner, file.getCreatedTime().getTime(),
                                            file.getLastModifiedBy(),
                                            file.getLastModified().getTime()
                        );
                    }
                    continue;
                }

                String description = file.getDescription();
                String permissions = file.getPermissions();
                if (file.getContentType().equals("collection")) {
                    Collection collection = adminRegistry.newCollection();
                    collection.setDescription(description);
                    for (ResProperty p : file.getProperties()) {
                        if (p.getKey().startsWith("registry.")) { continue; }
                        collection.setProperty(p.getKey(), p.getValue());
                    }
                    fullPath = adminRegistry.put(fullPath, collection);
                    setResourceRolePermissions(fullPath, permissions, roleMap);
                    setCollectionMetadata(fullPath,
                                          owner, file.getCreatedTime().getTime(),
                                          file.getLastModifiedBy(), file.getLastModified().getTime()
                    );
                    restoreFiles(file.getRegFiles(), rootPath, filesDir, roleMap);
                }
                else {
                    String checksum = file.getChecksum();
                    File resFile = new File(filesDir, checksum);
                    if (!resFile.exists()) {
                        throw new BackupRestoreException(
                            "Missing checksum file: " + checksum,
                            new FileNotFoundException(resFile.toString())
                        );
                    }
                    else {
                        Resource res = adminRegistry.newResource();
                        try {
                            res.setContentStream(new FileInputStream(resFile));
                        }
                        catch (FileNotFoundException ignored) {
                        }

                        res.setDescription(description);
                        res.setMediaType(file.getContentType());
                        for (ResProperty p : file.getProperties()) {
                            if (p.getKey().startsWith("registry.")) { continue; }
                            res.setProperty(p.getKey(), p.getValue());
                        }

                        boolean isPublic = Wso2Utils.isPublicAccessAllowed(permissions, registryUtils.getEveryoneRole());
                        res.setProperty(Constants.HTRC_PROP_PUBLIC, Boolean.toString(isPublic));

                        fullPath = adminRegistry.put(fullPath, res);
                        setResourceRolePermissions(fullPath, permissions, roleMap);
                        setResourceMetadata(fullPath,
                                            owner, file.getCreatedTime().getTime(),
                                            file.getLastModifiedBy(),
                                            file.getLastModified().getTime()
                        );

                        numFilesRestored++;
                    }
                }
            }
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Could not restore file(s)", e);
        }
    }

    /**
     * Creates the public file space in the registry
     *
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void createPublicFilespace() throws BackupRestoreException {
        try {
            String allowEveryonePermissions = String
                .format("%s:GDPa", registryUtils.getEveryoneRole());

            Collection publicCollection = adminRegistry.newCollection();
            String publicPath = adminRegistry.put(config.getPublicPath(), publicCollection);
            setResourceRolePermissions(publicPath, allowEveryonePermissions, null);

            Collection publicFilesCollection = adminRegistry.newCollection();
            publicFilesCollection.setDescription("Public files");
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Cannot create public space", e);
        }
    }

    /**
     * Sets the owner, created date, last updater, last updated date attributes for a collection
     *
     * @param collPath       The collection path
     * @param owner          The owner
     * @param createdDate    The created date
     * @param updater        The updater
     * @param lastUpdateDate The last updated date
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void setCollectionMetadata(String collPath, String owner, Date createdDate,
                                         String updater, Date lastUpdateDate)
        throws BackupRestoreException {
        try (Connection conn = dataSource.getConnection()) {
            PreparedStatement stmt = conn.prepareStatement(SET_COLL_META_SQL);
            stmt.setString(1, owner);
            stmt.setTimestamp(2, new java.sql.Timestamp(createdDate.getTime()));
            stmt.setString(3, updater);
            stmt.setTimestamp(4, new java.sql.Timestamp(lastUpdateDate.getTime()));
            stmt.setString(5, collPath);
            stmt.closeOnCompletion();
            int updated = stmt.executeUpdate();
            if (updated != 1) {
                throw new BackupRestoreException(
                    "Unexpected SQL response: setCollectionMetadata.updated=" + updated + " for "
                        + collPath);
            }
            conn.commit();
        }
        catch (SQLException e) {
            throw new BackupRestoreException(
                "Cannot update collection metadata for: " + collPath, e);
        }
    }

    /**
     * Sets the owner, created date, last updater, last updated date attributes for a resource
     *
     * @param resPath        The resource path
     * @param owner          The owner
     * @param createdDate    The created date
     * @param updater        The updater
     * @param lastUpdateDate The last updated date
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void setResourceMetadata(String resPath, String owner, Date createdDate,
                                       String updater, Date lastUpdateDate)
        throws BackupRestoreException {
        try (Connection conn = dataSource.getConnection()) {
            PreparedStatement stmt = conn.prepareStatement(SET_RES_META_SQL);
            stmt.setString(1, owner);
            stmt.setTimestamp(2, new java.sql.Timestamp(createdDate.getTime()));
            stmt.setString(3, updater);
            stmt.setTimestamp(4, new java.sql.Timestamp(lastUpdateDate.getTime()));
            stmt.setString(5, resPath);
            stmt.closeOnCompletion();
            int updated = stmt.executeUpdate();
            if (updated != 1) {
                throw new BackupRestoreException(
                    "Unexpected SQL response: setResourceMetadata.updated=" + updated + " for "
                        + resPath);
            }
            conn.commit();
        }
        catch (SQLException e) {
            throw new BackupRestoreException("Cannot update resource metadata for: " + resPath, e);
        }
    }

    /**
     * Creates a serializer (marshaller) for the `Volumes` of a workset
     *
     * @return The marshaller
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected Marshaller createVolumesMarshaller() throws BackupRestoreException {
        try {
            Marshaller marshaller = jaxbVolumesContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");

            return marshaller;
        }
        catch (JAXBException e) {
            throw new BackupRestoreException("Cannot create volumes marshaller", e);
        }
    }

    /**
     * Serializes a list of volumes and returns an InputStream for the result
     *
     * @param volumesList The list of volumes
     * @return The `InputStream` for the serialized list of volumes
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected InputStream createWorksetContentStream(List<Volume> volumesList)
        throws BackupRestoreException {
        try {
            Volumes volumes = new Volumes();
            volumes.getVolumes().addAll(volumesList);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            createVolumesMarshaller().marshal(volumes, baos);

            return new ByteArrayInputStream(baos.toByteArray());
        }
        catch (JAXBException e) {
            throw new BackupRestoreException("Cannot marshal volumes", e);
        }
    }

    /**
     * Restores a workset
     *
     * @param workset The workset
     * @throws BackupRestoreException Thrown if an error occurs during the restore process
     */
    protected void restoreWorkset(Workset workset) throws BackupRestoreException {
        try {
            WorksetMeta worksetMeta = workset.getMetadata();
            WorksetContent worksetContent = workset.getContent();

            String author = worksetMeta.getAuthor().toLowerCase();
            UserRegistry registry = registryUtils.getUserRegistry(author);

            Resource resource = registry.newResource();
            resource.setDescription(worksetMeta.getDescription());
            resource.setMediaType(HTRCMediaTypes.WORKSET_XML);
            int volumeCount = 0;

            if (worksetContent != null) {
                List<Volume> volumes = worksetContent.getVolumes();

                // check the volumes to make sure they contain not-obviously-invalid IDs
                for (Volume volume : volumes) {
                    String volumeId = volume.getId();
                    if (!VALID_HTRC_ID_REGEX.matcher(volumeId).matches()) {
                        worksetMeta.getTags().add("htrc::malformed");
                        numMalformedWorksets++;
                        break;
                    }
                }

                volumeCount = volumes.size();
                resource.setContentStream(createWorksetContentStream(volumes));
            }

            resource.setProperty(Constants.HTRC_PROP_VOLCOUNT, Integer.toString(volumeCount));
            resource.setProperty(Constants.HTRC_PROP_PUBLIC, Boolean.toString(worksetMeta.isPublic()));

            String worksetPath =
                String.format("%s/%s", config.getUserWorksetsPath(author), worksetMeta.getName());
            worksetPath = registry.put(worksetPath, resource);

            for (String tag : worksetMeta.getTags()) {
                registry.applyTag(worksetPath, tag);
            }

            if (worksetMeta.isPublic()) {
                String allowEveryoneReadPermissions = String
                    .format("%s:Gdpa", registryUtils.getEveryoneRole());
                setResourceRolePermissions(worksetPath, allowEveryoneReadPermissions, null);
            }

            setResourceMetadata(worksetPath,
                                author, worksetMeta.getCreated().getTime(),
                                worksetMeta.getLastModifiedBy(),
                                worksetMeta.getLastModified().getTime()
            );
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Cannot create resource from workset", e);
        }
    }
}
