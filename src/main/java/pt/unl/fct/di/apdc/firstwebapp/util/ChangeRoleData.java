package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangeRoleData {

    public String username;
    public String role;

    public ChangeRoleData() {

    }

    public ChangeRoleData(String username, String role) {
        this.username = username;
        this.role = role;
    }

    public boolean isValid() {
        return username != null && role != null
                && (role.equals("USER") || role.equals("GBO") || role.equals("GA") || role.equals("SU"));
    }
}
