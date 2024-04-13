package pt.unl.fct.di.apdc.firstwebapp.util;

public class RegisterData {

    public String username;
    public String password;
    public String confirmation;
    public String email;
    public String name;
    public String number;
    public String role;
    public String state = "INACTIVE";
    public String profile;
    public String occupation;
    public String workplace;
    public String address;
    public String postCode;
    public String nif;
    public String imagePath;

    public RegisterData() {

    }

    public RegisterData(String username, String password, String confirmation, String email, String name,
            String number, String occupation, String workplace, String address, String postCode, String nif,
            String imagePath, String profile) {
        this.username = username;
        this.password = password;
        this.confirmation = confirmation;
        this.email = email;
        this.name = name;
        this.number = number;
        this.role = "USER";
        this.occupation = occupation;
        this.workplace = workplace;
        this.address = address;
        this.postCode = postCode;
        this.nif = nif;
        this.imagePath = imagePath;
        this.profile = profile.toUpperCase();

    }

    public boolean isValid() {
        return !username.equals("") && !password.equals("") && !email.equals("") && !name.equals("")
                && !number.equals("");
    }

    public boolean isEmailValid() {
        return email.contains("@") && email.contains(".");
    }

    public boolean isNumberValid() {
        return number.length() == 9;
    }

    public boolean isProfileValid() {
        return this.profile.equalsIgnoreCase("PUBLIC") || this.profile.equals("PRIVATE")|| this.profile.equalsIgnoreCase("");
    }

    public boolean isPasswordValid() {
        return password.length() >= 8 && password.matches(".*\\d.*")
                && password.matches(".*[a-z].*") && password.matches(".*[A-Z].*") && password.equals(confirmation);
    }

}
