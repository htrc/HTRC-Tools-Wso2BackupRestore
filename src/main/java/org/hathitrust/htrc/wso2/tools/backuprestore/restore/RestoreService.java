package org.hathitrust.htrc.wso2.tools.backuprestore.restore;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import org.apache.http.HttpStatus;
import org.hathitrust.htrc.wso2.tools.backuprestore.BackupRestore;
import org.hathitrust.htrc.wso2.tools.backuprestore.exceptions.BackupRestoreException;

/**
 * Service that can be used for invoking the restore action
 *
 * @author capitanu
 */
public class RestoreService extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {

        resp.setContentType(MediaType.TEXT_PLAIN);

        String backupPath = req.getParameter("backupDir");
        if (backupPath == null || backupPath.isEmpty()) {
            resp.sendError(HttpStatus.SC_BAD_REQUEST, "Missing or empty 'backupDir' parameter");
            return;
        }

        File backupDir = new File(backupPath);
        if (!backupDir.exists()) {
            resp.sendError(HttpStatus.SC_BAD_REQUEST, "Path not found: " + backupPath);
            return;
        }

        BackupRestore backupRestore = (BackupRestore) getServletContext()
            .getAttribute(BackupRestore.class.getName());

        PrintWriter progressWriter = resp.getWriter();

        try {
            RestoreAction restoreAction = new RestoreAction(backupRestore, progressWriter);
            restoreAction.restore(backupDir);
        } catch (BackupRestoreException e) {
            e.printStackTrace(progressWriter);
            progressWriter.flush();
            resp.setStatus(HttpStatus.SC_METHOD_FAILURE);
            return;
        }

        progressWriter.flush();
        resp.setStatus(HttpStatus.SC_OK);
    }
}
