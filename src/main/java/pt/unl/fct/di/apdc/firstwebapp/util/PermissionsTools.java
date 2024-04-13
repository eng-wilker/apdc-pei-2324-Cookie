package pt.unl.fct.di.apdc.firstwebapp.util;

public class PermissionsTools {
    public static final String SU = "SU";
    public static final String GA = "GA";
    public static final String GBO = "GBO";
    public static final String USER = "USER";

    public static boolean canRemoveUser(String  role, String targetRole, String user, String targetUser) {
        switch (role) {
            case SU:
                return true;
            case GA:
                return targetRole.equals(GBO) || targetRole.equals(USER);
            case GBO:
                return false;
            case USER:
                return user.equals(targetUser);
            default:
                return false;
        }
    }

    public static boolean canModifyUser(String user, String targetUser) {
        switch (user) {
            case SU:
                return true;
            case GA:
                return targetUser.equals(GBO) || targetUser.equals(USER);
            case GBO:
                return targetUser.equals(USER);
            case USER:
                return false;
            default:
                return false;
        }
    }

    public static boolean canModifyState(String user, String targetUser) {
        switch (user) {
            case SU:
                return true;
            case GA:
                return targetUser.equals(GBO) || targetUser.equals(USER);
            case GBO:
                return targetUser.equals(USER);
            case USER:
                return false;
            default:
                return false;
        }
    }

    public static boolean canModifyRole(String user, String targetUser, String targetRole) {
        switch (user) {
            case SU:
                return true;
            case GA:
                return targetUser.equals(GBO) || targetUser.equals(USER) &&( targetRole.equals(USER)|| targetRole.equals(GBO));
            case GBO:
                return false;
            case USER:
                return false;
            default:
                return false;
        }
    }

    public static boolean canSeeUser(String userRole, String targetRole) {
        switch (userRole) {
            case SU:
                return true;
            case GA:
                return targetRole.equals(USER)|| targetRole.equals(GBO)|| targetRole.equals(GA);
            case GBO:
                return targetRole.equals(USER);
            case USER:
                return targetRole.equals(USER);
            default:
                return false;
        }
    }
}
