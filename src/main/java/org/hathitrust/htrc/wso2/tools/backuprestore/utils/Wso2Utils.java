package org.hathitrust.htrc.wso2.tools.backuprestore.utils;

import java.util.LinkedList;
import java.util.List;
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
}