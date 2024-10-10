package pkg;

import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

public class User {
	private static final Logger logger = Logger.getLogger(User.class.getName());
    private Set<String> existingUsernames = new HashSet<>(); // Simulating a database of usernames
    private Set<String> existingEmails = new HashSet<>(); // Simulating a database of emails

    public boolean validateUser(String username, String password, String email) {
        try {
            if (!isValidUsername(username)) {
                logger.warning("Username validation failed: must be between 5 and 20 characters.");
                return false;
            }
            if (existingUsernames.contains(username)) {
                logger.warning("Username validation failed: username already exists.");
                return false;
            }
            if (!isValidPassword(password)) {
                logger.warning("Password validation failed: must contain at least one special character.");
                return false;
            }
            if (!isValidEmail(email)) {
                logger.warning("Email validation failed: invalid email format.");
                return false;
            }
            if (existingEmails.contains(email)) {
                logger.warning("Email validation failed: email already exists.");
                return false;
            }

            // Log successful registration attempt
            logger.info("User registration successful for username: " + username);
            // Register the new user (in a real scenario, save to the database)
            existingUsernames.add(username);
            existingEmails.add(email);
        } catch (NullPointerException e) {
            logger.severe("Error: Input cannot be null - " + e.getMessage());
            return false;
        } catch (Exception e) {
            logger.severe("Unexpected error: " + e.getMessage());
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

    // Helper method to validate email format
    private boolean isValidEmail(String email) {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null.");
        }
        return email.matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$");
    }
    public static void main(String[] args) {
        User validator = new User();

        // Test validation
        try {
            String username = "johndoe";
            String email = "johndoe@gmail.com";
            String password = "password123!";
            if (validator.validateUser(username, password,email)) {
                System.out.println("User validation successful.");
            } else {
                System.out.println("User validation failed.");
            }
        } catch (Exception e) {
            System.out.println("Validation error: " + e.getMessage());
        }
    }
}
