package org.hathitrust.htrc.wso2.tools.backuprestore.exceptions;

public class BackupRestoreException extends Exception {

    public BackupRestoreException(String message) {
        super(message);
    }

    public BackupRestoreException(Throwable cause) {
        super(cause);
    }

    public BackupRestoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
