package pt.unl.fct.di.apdc.firstwebapp.util;

import org.checkerframework.checker.units.qual.t;

public class ChangeRoleData {

    public String username;
    public String role;
    public String cookie;

    public ChangeRoleData() {

    }

    public ChangeRoleData(String username, String role, String cookie) {
        this.username = username;
        this.role = role.toUpperCase();
        this.cookie = cookie;
    }

    public boolean isValidRole() {
        return !username.equals("") && !role.equals("")
                && (role.equals("USER") || role.equals("GBO") || role.equals("GA") || role.equals("SU"));
    }
}
