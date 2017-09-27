package org.hathitrust.htrc.wso2.tools.backuprestore.utils;

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;
import org.wso2.carbon.user.mgt.common.UIPermissionNode;

/**
 * Various utilities for working with WSO2
 *
 * @author capitanu
 */
public class Wso2Utils {

    /**
     * Converts a set of WSO2 permissions to their string representation
     *
     * @param permissionNode The WSO2 permissions
     * @return The permissions as strings
     */
    public static List<String> parsePermissions(UIPermissionNode permissionNode) {
        List<String> permissions = new LinkedList<>();
        parsePermissions(permissionNode, permissions);

        return permissions;
    }

    /**
     * Recurses a WSO2 permission tree and converts permissions to their string representation
     *
     * @param permissionNode The WSO2 permissions tree node to start at
     * @param permissions    The permission string accumulator
     */
    private static void parsePermissions(UIPermissionNode permissionNode,
                                         List<String> permissions) {
        if (permissionNode.isSelected()) {
            permissions.add(permissionNode.getResourcePath());
        }
        if (permissionNode.getNodeList() != null) {
            for (UIPermissionNode node : permissionNode.getNodeList()) {
                parsePermissions(node, permissions);
            }
        }
    }

    /**
     * Checks whether the given set of permissions indicate that everyone is allowed access
     *
     * @param permissions The permissions to check
     * @param everyoneRoleName The name of the "everyone" role
     * @return True if public access allowed, False otherwise
     */
    public static boolean isPublicAccessAllowed(String permissions, String everyoneRoleName) {
        boolean isPublic = false;

        for (String rolePerms : permissions.split(Pattern.quote("|"))) {
            String[] permParts = rolePerms.split(":");
            String role = permParts[0];
            String perms = permParts[1];
            if (role.equalsIgnoreCase(everyoneRoleName) && perms.contains("G")) {
                isPublic = true;
                break;
            }
        }

        return isPublic;
    }
}