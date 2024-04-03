package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangePasswordData {

    public String username;
    public String oldPassword;
    public String newPassword;
    public String confirmPassword;

    public ChangePasswordData() {

    }

    public ChangePasswordData(String username, String oldPassword, String newPassword, String confirmPassword) {
        this.username = username;
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
        this.confirmPassword = confirmPassword;
    }

    public boolean isValid() {
        return username != null && oldPassword != null && newPassword != null && confirmPassword != null;
    }

    public boolean isPasswordValid() {
        return newPassword != null && newPassword.length() >= 8 && newPassword.matches(".*\\d.*")
                && newPassword.matches(".*[a-z].*") && newPassword.matches(".*[A-Z].*");
    }

    public boolean isPasswordMatch() {
        return newPassword.equals(confirmPassword);
    }
}
