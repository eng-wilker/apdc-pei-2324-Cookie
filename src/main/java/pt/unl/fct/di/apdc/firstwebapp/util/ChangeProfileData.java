package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangeProfileData {

    public String targetUser;
    public String email;
    public String name;
    public String number;
    public String password;
    public String role;
    public String state;
    public String profile;
    public String occupation;
    public String workplace;
    public String address;
    public String postCode;
    public String nif;
    public String imagePath;
    public String cookie;

    public ChangeProfileData() {

    }

    public ChangeProfileData(String targetUser, String password, String email, String name, String number, String role,
            String state, String profile, String occupation, String workplace, String address, String postCode,
            String nif, String imagePath, String cookie) {
        this.targetUser = targetUser;
        this.email = email;
        this.name = name;
        this.number = number;
        this.password = password;
        this.role = role.toUpperCase();
        this.state = state.toUpperCase();
        this.profile = profile.toUpperCase();
        this.occupation = occupation;
        this.workplace = workplace;
        this.address = address;
        this.postCode = postCode;
        this.nif = nif;
        this.imagePath = imagePath;
        this.cookie = cookie;

    }

    public boolean isStateValid() {
        return state.equals("") || (state.equals("ACTIVE") || state.equals("INACTIVE"));
    }
    public boolean isProfileValid() {
        return profile.equalsIgnoreCase("PUBLIC") || profile.equals("PRIVATE")|| profile.equalsIgnoreCase("");
    }
    public boolean isRoleValid() {
        return role.equals("USER") || role.equals("GBO") || role.equals("GA") || role.equals("SU")|| role.equals("");
    }

    public boolean isEmailValid() {
        return email != null && email.contains("@") && email.contains(".");
    }

    public boolean isNumberValid() {
        return number != null && number.length() == 9;
    }

}
