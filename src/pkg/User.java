package pkg;

public class User {
	public boolean validateUser(String username, String password) {
        try {
            if (!isValidUsername(username)) {
                System.out.println("Username validation failed: must be between 5 and 20 characters.");
                return false;
            }
            if (!isValidPassword(password)) {
                System.out.println("Password validation failed: must contain at least one special character.");
                return false;
            }
        } catch (NullPointerException e) {
            System.out.println("Error: Input cannot be null - " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
            return false;
        }
        return true;
    }

    // Helper method to check username length
    private boolean isValidUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("Username cannot be null.");
        }
        return username.length() >= 5 && username.length() <= 20;
    }

    // Helper method to check if password contains special characters
    private boolean isValidPassword(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null.");
        }
        return password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*");
    }
    public static void main(String[] args) {
        User validator = new User();

        // Test validation
        try {
            String username = "johndoe";
            String password = "password123!";
            if (validator.validateUser(username, password)) {
                System.out.println("User validation successful.");
            } else {
                System.out.println("User validation failed.");
            }
        } catch (Exception e) {
            System.out.println("Validation error: " + e.getMessage());
        }
    }
}
