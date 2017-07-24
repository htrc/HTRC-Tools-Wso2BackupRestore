# HTRC-Tools-WSO2BackupRestore
Tool for backing up and restoring users, roles, files, and worksets to/from a WSO2 server instance.

# Build

`mvn clean package`

This builds the WAR artifact package, which can be found in `target/wso2br.war`

# Deploy

Copy the WAR file to `<WSO2DIR>/repository/deployment/server/webapps/`

**IMPORTANT**  
The following configuration changes are necessary to allow the backup process to retrieve all users 
and roles (the configuration limits the maximum number of users and roles that can be retrieved via
the API)

In file `<WSO2HOME>/repository/conf/user-mgt.xml`, for the `<UserStoreManager>` definition that's 
active, the following properties need to be set:
```xml
    <Property name="MaxRoleNameListLength">0</Property>
    <Property name="MaxUserNameListLength">0</Property>
```

# API

## Backup

`POST <WSO2URL>/wso2br/services/backup?backupDir=<DIR>`

This performs a backup of the WSO2 server running at `<WSO2URL>` and writes the backup data to `<DIR>`.

*Note:* `<DIR>` must not exist beforehand or the backup operation will abort (will not overwrite 
a previous backup for safety reasons)

## Restore

`POST <WSO2URL>/wso2br/services/restore?backupDir=<DIR>`

This performs a restore of the backup data from `<DIR>` to the WSO2 server referenced by `<WSO2URL>`.

*Note:* The WSO2 server **must** be restarted after the restore operation is completed.