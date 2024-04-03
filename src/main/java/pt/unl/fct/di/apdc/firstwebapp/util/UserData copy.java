package pt.unl.fct.di.apdc.firstwebapp.util;


public class UserData {

    public String username;
    public String password;
    public String email;
    public String name;
    public String number;
    public String role;
    public String state = "inactive"; // "active" or "inactive

    public UserData() {

    }

    public UserData(String username, String password, String email, String name, String number) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.name = name;
        this.number = number;
        this.role = "USER";
    }

    public boolean isValid() {
        return username != null && password != null && email != null && name != null && number != null;
    }

    public boolean isEmailValid() {
        return email != null && email.contains("@") && email.contains(".");
    }

    public boolean isNumberValid() {
        return number != null && number.length() == 9;
    }

    public boolean isPasswordValid() {
        return password != null && password.length() >= 8 && password.matches(".*\\d.*")
                && password.matches(".*[a-z].*") && password.matches(".*[A-Z].*");
    }

}
