package org.hathitrust.htrc.wso2.tools.backuprestore.backup;

import edu.illinois.i3.htrc.registry.entities.backup.Backup;
import edu.illinois.i3.htrc.registry.entities.backup.BackupMeta;
import edu.illinois.i3.htrc.registry.entities.backup.PublicFilespace;
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
import edu.illinois.i3.htrc.registry.entities.workset.Worksets;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Pattern;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import org.apache.commons.io.IOUtils;
import org.hathitrust.htrc.wso2.tools.backuprestore.BackupRestore;
import org.hathitrust.htrc.wso2.tools.backuprestore.Constants;
import org.hathitrust.htrc.wso2.tools.backuprestore.RegistryExtensionConfig;
import org.hathitrust.htrc.wso2.tools.backuprestore.exceptions.BackupRestoreException;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.RegistryUtils;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.Utils;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.Utils.StringJoiner;
import org.hathitrust.htrc.wso2.tools.backuprestore.utils.Wso2Utils;
import org.wso2.carbon.registry.core.ActionConstants;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.Tag;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.secure.AuthorizationFailedException;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.registry.core.utils.AccessControlConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.AuthorizationManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.mgt.UserRealmProxy;
import org.wso2.carbon.user.mgt.common.UIPermissionNode;
import org.wso2.carbon.user.mgt.common.UserAdminException;

/**
 * Defines how backups are performed
 *
 * @author capitanu
 */
public class BackupAction {

    private final PrintWriter progressWriter;
    private final RegistryUtils registryUtils;
    private final RegistryExtensionConfig config;
    private final UserRegistry adminRegistry;
    private final UserStoreManager userStoreManager;
    private final AuthorizationManager authorizationManager;
    private final UserRealmProxy userRealmProxy;
    private final JAXBContext jaxbVolumesContext;

    /**
     * Backup constructor
     *
     * @param backupRestore  Instance holding configuration and other useful references
     * @param progressWriter The writer where progress information is written to
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    public BackupAction(BackupRestore backupRestore, PrintWriter progressWriter)
        throws BackupRestoreException {
        this.progressWriter = progressWriter;
        this.registryUtils = backupRestore.getRegistryUtils();
        this.config = backupRestore.getConfig();

        try {
            this.adminRegistry = registryUtils.getAdminRegistry();
            UserRealm userRealm = adminRegistry.getUserRealm();
            this.userRealmProxy = new UserRealmProxy(userRealm);
            this.userStoreManager = userRealm.getUserStoreManager();
            this.authorizationManager = userRealm.getAuthorizationManager();
            this.jaxbVolumesContext = JAXBContext.newInstance(Volumes.class, Volume.class);
        }
        catch (org.wso2.carbon.user.core.UserStoreException | RegistryException | JAXBException e) {
            throw new BackupRestoreException("Could not initialize the backup function", e);
        }
    }

    /**
     * Performs the backup
     *
     * @param backupDir The destination directory to write the backup to
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    public void backup(File backupDir) throws BackupRestoreException {
        File filesDir = new File(backupDir, "files");
        filesDir.mkdirs();

        log("Creating backup...");
        BackupMeta backupMeta = createBackupMeta();

        Set<String> excludedRoles = new HashSet<>();
        excludedRoles.add(backupMeta.getAdminRoleName());
        excludedRoles.add(backupMeta.getEveryoneRole().getName());
        excludedRoles.add("everyone");

        log("Retrieving the list of roles...");
        List<Role> roles = getAllRoles(excludedRoles);
        log("Retrieved %,d roles", roles.size());

        Set<String> excludedUsers = new HashSet<>();
        excludedUsers.add(backupMeta.getAdminUserName());

        log("Retrieving the list of users...");
        Set<String> excludedProfileClaims = new HashSet<>();
        excludedProfileClaims.add("http://wso2.org/claims/role");
        excludedProfileClaims.add("http://wso2.org/claims/userid");
        List<User> users = getAllUsers(excludedUsers, excludedProfileClaims);
        log("Retrieved %,d users", users.size());

        List<UserFiles> allUsersFiles = new Vector<>();
        List<Workset> allUsersWorksets = new Vector<>();

        int count = 0;
        int total = users.size();

        for (User user : users) {
            String userName = user.getName();
            log("Backing up user files for '%s'...", userName);
            UserFiles userFiles = getUserFiles(userName);
            if (userFiles != null) {
                allUsersFiles.add(userFiles);
                String regUserFiles = config.getUserFilesPath(userName);
                backupFiles(userFiles.getRegFiles(), regUserFiles, filesDir);
            }

            log("Backing up user worksets for '%s'...", userName);
            Worksets userWorksets = getUserWorksets(userName);
            if (userWorksets != null) {
                allUsersWorksets.addAll(userWorksets.getWorksets());
            }

            count++;

            if (count % 100 == 0) {
                double percentComplete = (double) count / total * 100;
                log("User backup progress: %.2f complete", percentComplete);
            }
        }

        log("Backing up public files...");
        PublicFilespace publicFilespace = getPublicFilespace();
        String regPublicFiles = config.getPublicFilesPath();
        backupFiles(publicFilespace.getRegFiles(), regPublicFiles, filesDir);

        Backup backup = new Backup();
        backup.setMetadata(backupMeta);
        backup.setRoles(roles);
        backup.setUsers(users);
        backup.setUserFilespace(allUsersFiles);
        backup.setPublicFilespace(publicFilespace);
        backup.setWorksets(allUsersWorksets);

        log("Saving backup file to %s...", backupDir);
        saveBackup(backup, backupDir);

        log("All done!");
    }

    /**
     * Saves the backup
     *
     * @param backup    The backup instance
     * @param backupDir The directory to save the backup to
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected void saveBackup(Backup backup, File backupDir) throws BackupRestoreException {
        try {
            backupDir.mkdirs();

            JAXBContext context = JAXBContext.newInstance(Backup.class);
            Marshaller marshaller = context.createMarshaller();

            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");

            try (Writer writer = new FileWriter(new File(backupDir, "backup.xml"))) {
                marshaller.marshal(backup, writer);
            }
        }
        catch (IOException | JAXBException e) {
            throw new BackupRestoreException("Error while saving backup", e);
        }
    }

    /**
     * Retrieves the file information from the public file space
     *
     * @return An instance holding the file information from the public file space
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected PublicFilespace getPublicFilespace() throws BackupRestoreException {
        try {
            String regPublicFiles = config.getPublicFilesPath();
            PublicFilespace publicFilespace = new PublicFilespace();

            RegFile publicFilesRoot = treeWalk(regPublicFiles, regPublicFiles, true);
            publicFilespace.setRegFiles(publicFilesRoot.getRegFiles());

            return publicFilespace;
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Error retrieving public files", e);
        }
    }

    /**
     * Deserializes the volumes stored in the registry into a `Volumes` object
     *
     * @param resource The registry resource
     * @return The `Volumes` object
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected Volumes getWorksetVolumesFromResource(Resource resource) throws RegistryException {
        try {
            Volumes result = null;

            if (resource.getContent() != null) {
                try (InputStream contentStream = resource.getContentStream()) {
                    result = (Volumes) jaxbVolumesContext.createUnmarshaller()
                                                         .unmarshal(contentStream);
                }
            }

            return result;
        }
        catch (JAXBException | IOException e) {
            throw new RegistryException("Error unmarshalling workset volumes", e);
        }
    }

    /**
     * Deserializes the workset content from a registry resource
     *
     * @param resource The registry resource
     * @return The `WorksetContent` instance
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected WorksetContent getWorksetContentFromResource(Resource resource)
        throws RegistryException {
        WorksetContent worksetContent = new WorksetContent();

        Volumes volumes = getWorksetVolumesFromResource(resource);
        if (volumes != null) {
            worksetContent.setVolumes(volumes.getVolumes());
        }
        else {
            worksetContent = null;
        }

        return worksetContent;
    }

    /**
     * Deserializes a Workset from a registry resource
     *
     * @param resource The registry resource
     * @return The `Workset` instance
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected Workset getWorksetFromResource(Resource resource) throws RegistryException {
        WorksetMeta worksetMeta = getWorksetMetaFromResource(resource);
        WorksetContent worksetContent = getWorksetContentFromResource(resource);

        Workset workset = new Workset();
        workset.setMetadata(worksetMeta);
        workset.setContent(worksetContent);

        return workset;
    }

    /**
     * Deserializes the workset metadata from a registry resource
     *
     * @param resource The registry resource
     * @return The `WorksetMeta` instance
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected WorksetMeta getWorksetMetaFromResource(Resource resource) throws RegistryException {
        String resPath = resource.getPath();
        Tag[] tags = adminRegistry.getTags(resPath);
        String name = resPath.substring(resPath.lastIndexOf("/") + 1);

        WorksetMeta worksetMeta = new WorksetMeta();
        worksetMeta.setName(name);
        worksetMeta.setDescription(resource.getDescription());
        worksetMeta.setAuthor(resource.getAuthorUserName());
        String sVolCount = resource.getProperty(Constants.HTRC_PROP_VOLCOUNT);
        int volumeCount = (sVolCount != null) ? Integer.parseInt(sVolCount) : -1;
        worksetMeta.setVolumeCount(volumeCount);

        String permissions = getPermissionsForResource(resource.getId());
        String everyoneRole = userStoreManager.getRealmConfiguration().getEveryOneRoleName();
        boolean isPublic = false;
        for (String rolePerms : permissions.split(Pattern.quote("|"))) {
            String[] permParts = rolePerms.split(":");
            String role = permParts[0];
            String perms = permParts[1];
            if (role.equalsIgnoreCase(everyoneRole) && perms.contains("G")) {
                isPublic = true;
                break;
            }
        }
        worksetMeta.setPublic(isPublic);

        worksetMeta.setLastModifiedBy(resource.getLastUpdaterUserName());

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(resource.getLastModified());
        worksetMeta.setLastModified(calendar);

        calendar = Calendar.getInstance();
        calendar.setTime(resource.getCreatedTime());
        worksetMeta.setCreated(calendar);

        List<String> resTags = worksetMeta.getTags();
        for (Tag tag : tags) {
            resTags.add(tag.getTagName());
        }

        return worksetMeta;
    }

    /**
     * Retrieves all worksets for a particular user
     *
     * @param userName The user name
     * @return The `Worksets` instance
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected Worksets getUserWorksets(String userName) throws BackupRestoreException {
        try {
            String regUserWorksets = config.getUserWorksetsPath(userName);
            Worksets userWorksets = null;

            if (adminRegistry.resourceExists(regUserWorksets)) {
                Collection userWorksetCollection = (Collection) adminRegistry.get(regUserWorksets);
                userWorksets = new Worksets();
                List<Workset> worksets = userWorksets.getWorksets();

                for (String child : userWorksetCollection.getChildren()) {
                    try {
                        Resource resource = adminRegistry.get(child);
                        Workset workset = getWorksetFromResource(resource);
                        worksets.add(workset);
                    }
                    catch (AuthorizationFailedException afe) {
                        log("Error: AuthorizationFailed for '%s' (Message: %s) - ignoring",
                            child, afe.getMessage()
                        );
                    }
                }
            }

            return userWorksets;
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Error retrieving user worksets for: " + userName, e);
        }
    }

    /**
     * Checks whether a registry resource is a symbolic link to another resource
     *
     * @param path The resource path
     * @return True if yes, False otherwise
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected boolean isSymlink(String path) throws RegistryException {
        return Boolean.parseBoolean(adminRegistry.get(path).getProperty("registry.link"));
    }

    /**
     * Saves a copy of a set of registry files to disk
     *
     * @param files    The files
     * @param rootPath The root path for the files
     * @param filesDir The directory where to save the files
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected void backupFiles(List<RegFile> files, String rootPath, File filesDir)
        throws BackupRestoreException {
        try {
            for (RegFile file : files) {
                String fullPath = rootPath + file.getParentPath() + file.getName();
                if (isSymlink(fullPath)) {
                    continue;
                }
                if (file.getContentType().equals("collection")) {
                    backupFiles(file.getRegFiles(), rootPath, filesDir);
                }
                else {
                    Resource resource = adminRegistry.get(fullPath);
                    String checksum = file.getChecksum();
                    File resFile = new File(filesDir, checksum);
                    if (!resFile.exists()) {
                        try (InputStream contentStream = resource.getContentStream();
                             OutputStream outputStream = new FileOutputStream(resFile)) {
                            IOUtils.copy(contentStream, outputStream);
                        }
                        catch (Exception e) {
                            throw new RegistryException(
                                "Error retrieving resource content stream", e);
                        }
                    }
                }
            }
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Error while backing up files", e);
        }
    }

    /**
     * Recurses a folder (registry collection) hierarchy and maps it to an object structure
     *
     * @param filesPath The path to start at
     * @param path      The path to relative-ize the founds paths to
     * @param recursive True to recurse, False otherwise
     * @return The `RegFile` object structure mirroring the registry structure
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected RegFile treeWalk(String filesPath, String path, boolean recursive)
        throws RegistryException {
        Resource resource = adminRegistry.get(path);
        RegFile entry = getResourceAsRegFile(resource, filesPath);
        if (resource instanceof Collection) {
            Collection folder = (Collection) resource;
            List<RegFile> folderEntries = new ArrayList<>(folder.getChildCount());
            for (String child : folder.getChildren()) {
                RegFile childEntry;
                if (recursive) {
                    childEntry = treeWalk(filesPath, child, recursive);
                }
                else {
                    Resource childResource = adminRegistry.get(child);
                    childEntry = getResourceAsRegFile(childResource, filesPath);
                }

                if (childEntry != null) {
                    folderEntries.add(childEntry);
                }
            }

            entry.setRegFiles(folderEntries);
        }

        return entry;
    }

    /**
     * Retrieves the set of permissions for a given registry resource
     *
     * @param resId The resource id
     * @return The string encoding the resource' permissions (GDPA = get, delete, put, authorize);
     * upper case means the permission is allowed, lowercase means the permission is denied
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected String getPermissionsForResource(String resId) throws RegistryException {
        try {
            String adminRoleName = registryUtils.getAdminRole();

            String[] allowedGet = authorizationManager
                .getAllowedRolesForResource(resId, ActionConstants.GET);
            String[] allowedDelete = authorizationManager
                .getAllowedRolesForResource(resId, ActionConstants.DELETE);
            String[] allowedPut = authorizationManager
                .getAllowedRolesForResource(resId, ActionConstants.PUT);
            String[] allowedAuthorize = authorizationManager.getAllowedRolesForResource(
                resId,
                AccessControlConstants.AUTHORIZE
            );

            String[] deniedGet = authorizationManager
                .getDeniedRolesForResource(resId, ActionConstants.GET);
            String[] deniedDelete = authorizationManager
                .getDeniedRolesForResource(resId, ActionConstants.DELETE);
            String[] deniedPut = authorizationManager
                .getDeniedRolesForResource(resId, ActionConstants.PUT);
            String[] deniedAuthorize = authorizationManager.getDeniedRolesForResource(
                resId,
                AccessControlConstants.AUTHORIZE
            );

            Map<String, String> rolePerms = new HashMap<>();
            for (String roleName : allowedGet) {
                if (roleName.equalsIgnoreCase(adminRoleName)) { continue; }
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "G");
            }
            for (String roleName : allowedDelete) {
                if (roleName.equalsIgnoreCase(adminRoleName)) { continue; }
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "D");
            }
            for (String roleName : allowedPut) {
                if (roleName.equalsIgnoreCase(adminRoleName)) { continue; }
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "P");
            }
            for (String roleName : allowedAuthorize) {
                if (roleName.equalsIgnoreCase(adminRoleName)) { continue; }
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "A");
            }
            for (String roleName : deniedGet) {
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "g");
            }
            for (String roleName : deniedDelete) {
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "d");
            }
            for (String roleName : deniedPut) {
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "p");
            }
            for (String roleName : deniedAuthorize) {
                rolePerms.put(roleName, Utils.getOrDefault(rolePerms, roleName, "") + "a");
            }

            StringJoiner joiner = new StringJoiner("|");
            for (Entry<String, String> entry : rolePerms.entrySet()) {
                joiner.add(String.format("%s:%s", entry.getKey(), entry.getValue()));
            }

            return joiner.toString();
        }
        catch (UserStoreException e) {
            throw new RegistryException("Error retrieving resource permissions for: " + resId, e);
        }
    }

    /**
     * Encodes a registry resource into a `RegFile` object
     *
     * @param resource  The registry resource
     * @param filesPath The path to relative-ize to
     * @return The `RegFile` instance
     * @throws RegistryException Thrown if an error occurs while accessing the registry
     */
    protected RegFile getResourceAsRegFile(Resource resource, String filesPath)
        throws RegistryException {
        String resPath = resource.getPath();
        assert (resPath.startsWith(filesPath));
        String relPath = resPath.substring(filesPath.length());
        RegFile regFile = new RegFile();
        if (resource instanceof Collection) {
            regFile.setContentType("collection");
        }
        else {
            regFile.setContentType(resource.getMediaType());
            try (InputStream contentStream = resource.getContentStream()) {
                regFile.setChecksum(Utils.sha1(contentStream));
            }
            catch (Exception e) {
                throw new RegistryException("Error retrieving resource content stream", e);
            }
        }
        String parentPath =
            relPath.isEmpty() ? null : relPath.substring(0, relPath.lastIndexOf("/") + 1);
        regFile.setParentPath(parentPath);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(resource.getCreatedTime());
        regFile.setCreatedTime(calendar);

        calendar = Calendar.getInstance();
        calendar.setTime(resource.getLastModified());
        regFile.setLastModified(calendar);

        regFile.setAuthor(resource.getAuthorUserName());
        regFile.setLastModifiedBy(resource.getLastUpdaterUserName());
        regFile.setDescription(resource.getDescription());
        String name = parentPath == null ? "/" : relPath.substring(parentPath.length());
        regFile.setName(name);
        regFile.setPermissions(getPermissionsForResource(resource.getId()));

        List<ResProperty> propertyList = regFile.getProperties();
        Properties properties = resource.getProperties();
        for (Object obj : properties.keySet()) {
            ResProperty resProperty = new ResProperty();
            String key = obj.toString();
            resProperty.setKey(key);
            resProperty.setValue(resource.getProperty(key));
            propertyList.add(resProperty);
        }

        return regFile;
    }

    /**
     * Retrieves all user files
     *
     * @param userName The user name
     * @return The `UserFiles` instance containing references to the user's files
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected UserFiles getUserFiles(String userName) throws BackupRestoreException {
        try {
            String regUserFiles = config.getUserFilesPath(userName);
            UserFiles userFiles = null;

            if (adminRegistry.resourceExists(regUserFiles)) {
                RegFile userFilesRoot = treeWalk(regUserFiles, regUserFiles, true);
                userFiles = new UserFiles();
                userFiles.setUser(userName);
                userFiles.setRegFiles(userFilesRoot.getRegFiles());
            }

            return userFiles;
        }
        catch (RegistryException e) {
            throw new BackupRestoreException("Error retrieving user files for: " + userName, e);
        }
    }

    /**
     * Retrieves a user's profile claims
     *
     * @param userName              The user name
     * @param excludedProfileClaims The profile claims to exclude
     * @return The list of profile claims
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected List<Claim> getUserProfileClaims(String userName, Set<String> excludedProfileClaims)
        throws BackupRestoreException {
        try {
            org.wso2.carbon.user.core.claim.Claim[] wso2Claims =
                userStoreManager.getUserClaimValues(userName, "default");

            List<Claim> userClaims = new Vector<>();
            for (org.wso2.carbon.user.core.claim.Claim wso2Claim : wso2Claims) {
                String claimUri = wso2Claim.getClaimUri();
                if (excludedProfileClaims.contains(claimUri)) { continue; }

                Claim claim = new Claim();
                claim.setUri(claimUri);
                claim.setValue(wso2Claim.getValue());
                userClaims.add(claim);
            }

            return userClaims;
        }
        catch (UserStoreException e) {
            throw new BackupRestoreException(
                "Error retrieving user profile claims for: " + userName, e);
        }
    }

    /**
     * Retrieves the list of users (with optional exclusions)
     *
     * @param excludedUsers         The set of users to exclude
     * @param excludedProfileClaims The set of profile claims to exclude
     * @return The list of users
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected List<User> getAllUsers(Set<String> excludedUsers, Set<String> excludedProfileClaims)
        throws BackupRestoreException {
        try {
            String[] wso2Users = userStoreManager.listUsers("*", Integer.MAX_VALUE);
            List<User> users = new ArrayList<>(wso2Users.length);

            for (String userName : wso2Users) {
                if (excludedUsers.contains(userName)) {
                    continue;
                }

                List<Claim> userProfileClaims =
                    getUserProfileClaims(userName, excludedProfileClaims);
                List<String> userRoles =
                    Arrays.asList(userStoreManager.getRoleListOfUser(userName));
                String userHome = config.getUserHomePath(userName);

                User user = new User();
                user.setName(userName);
                user.setClaims(userProfileClaims);
                user.setRoles(userRoles);
                user.setHasHome(adminRegistry.resourceExists(userHome));

                users.add(user);
            }

            return users;
        }
        catch (UserStoreException | RegistryException e) {
            throw new BackupRestoreException("Error while retrieving users", e);
        }
    }

    /**
     * Retrieves the list of roles (with optional exclusions)
     *
     * @param excludedRoles The set of roles to exclude
     * @return The list of roles
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected List<Role> getAllRoles(Set<String> excludedRoles) throws BackupRestoreException {
        try {
            List<Role> roles = new ArrayList<>();

            for (String roleName : userStoreManager.getRoleNames()) {
                if (excludedRoles.contains(roleName)) { continue; }

                List<String> rolePermissions = getRolePermissions(roleName);

                Role role = new Role();
                role.setName(roleName);
                role.setPermissions(rolePermissions);

                roles.add(role);
            }

            return roles;
        }
        catch (UserAdminException | UserStoreException e) {
            throw new BackupRestoreException("Cannot retrieve roles", e);
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
     * Retrieves all permissions for a role
     *
     * @param role The role name
     * @return The list of permissions
     * @throws UserAdminException Thrown if an error occurs while retrieving the role permissions
     */
    protected List<String> getRolePermissions(String role)
        throws UserAdminException {
        int tenantId = registryUtils.getTenantId();
        UIPermissionNode rolePermissions = userRealmProxy
            .getRolePermissions(role, tenantId);
        return Wso2Utils.parsePermissions(rolePermissions);
    }

    /**
     * Creates the backup metadata
     *
     * @return The backup metadata
     * @throws BackupRestoreException Thrown if an error occurs during the backup process
     */
    protected BackupMeta createBackupMeta() throws BackupRestoreException {
        try {
            RealmConfiguration realmConfiguration = userStoreManager.getRealmConfiguration();
            String adminUserName = realmConfiguration.getAdminUserName();
            String adminRoleName = realmConfiguration.getAdminRoleName();
            String everyoneRoleName = realmConfiguration.getEveryOneRoleName();

            Role everyoneRole = new Role();
            everyoneRole.setName(everyoneRoleName);
            everyoneRole.setPermissions(getRolePermissions(everyoneRoleName));

            BackupMeta backupMeta = new BackupMeta();
            backupMeta.setVersion(Constants.BACKUP_VERSION);
            backupMeta.setCreatedAt(Calendar.getInstance());
            backupMeta.setAdminUserName(adminUserName);
            backupMeta.setAdminRoleName(adminRoleName);
            backupMeta.setEveryoneRole(everyoneRole);

            return backupMeta;
        }
        catch (UserAdminException e) {
            throw new BackupRestoreException("Cannot create backup meta", e);
        }
    }
}
