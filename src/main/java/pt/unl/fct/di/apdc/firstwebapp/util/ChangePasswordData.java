package pt.unl.fct.di.apdc.firstwebapp.util;

public class ChangePasswordData {

    public String oldPassword;
    public String newPassword;
    public String confirmPassword;
    public String cookie;

    public ChangePasswordData() {

    }

    public ChangePasswordData(String oldPassword, String newPassword, String confirmPassword, String cookie) {
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
        this.confirmPassword = confirmPassword;
        this.cookie = cookie;
    }

    public boolean isValid() {
        return oldPassword != null && newPassword != null && confirmPassword != null;
    }

    public boolean isPasswordValid() {
        return newPassword != null && newPassword.length() >= 8 && newPassword.matches(".*\\d.*")
                && newPassword.matches(".*[a-z].*") && newPassword.matches(".*[A-Z].*");
    }

    public boolean isPasswordMatch() {
        return newPassword.equals(confirmPassword);
    }
}
