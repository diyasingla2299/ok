
package com.ShopSphere.shop_sphere.service;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.ShopSphere.shop_sphere.exception.ResourceNotFoundException;
import com.ShopSphere.shop_sphere.model.User;
import com.ShopSphere.shop_sphere.repository.UserDao;

@Service
public class UserServiceImpl implements UserService {

    private final UserDao userDao;

    // Simple email regex (not exhaustive, good enough for most cases)
    private static final Pattern EMAIL_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    public UserServiceImpl(UserDao userDao) {
        this.userDao = userDao;
    }

    @Override
    public int createUser(User user) {
        validateForCreate(user);
        // Optional: prevent duplicates by email (if not enforced by DB)
        if (userExistsByEmail(user.getEmail())) {
            throw new RuntimeException("User with email already exists: " + user.getEmail());
        }

        int id = userDao.save(user);
        if (id <= 0) {
            throw new RuntimeException("Failed to create user with email: " + user.getEmail());
        }
        return id;
    }

    @Override
    public User getUserById(int userId) {
        if (userId <= 0) {
            throw new IllegalArgumentException("userId must be positive");
        }
        User user = userDao.findById(userId);
        if (user == null) {
            throw new ResourceNotFoundException("No user found for userId: " + userId);
        }
        return user;
    }

    @Override
    public User getUserByEmail(String email) {
        validateEmail(email);
        User user = userDao.findByEmail(email);
        if (user == null) {
            throw new ResourceNotFoundException("No user found for email: " + email);
        }
        return user;
    }

    @Override
    public List<User> getAllUsers() {
        return userDao.findAll();
    }

    @Override
    public int updateUser(User user) {
        validateForUpdate(user);

        // Ensure the record exists before updating
        User existing = userDao.findById(user.getUserId());
        if (existing == null) {
            throw new ResourceNotFoundException("Cannot update; user not found for userId: " + user.getUserId());
        }

        // Optional: if email is being changed, ensure uniqueness
        if (!existing.getEmail().equalsIgnoreCase(user.getEmail()) && userExistsByEmail(user.getEmail())) {
            throw new RuntimeException("Email already in use: " + user.getEmail());
        }

        int rows = userDao.update(user);
        if (rows <= 0) {
            throw new RuntimeException("Update failed for userId: " + user.getUserId());
        }
        return rows;
    }

    @Override
    public void deleteUser(int userId) {
        if (userId <= 0) {
            throw new IllegalArgumentException("userId must be positive");
        }
        int rows = userDao.delete(userId);
        if (rows <= 0) {
            throw new ResourceNotFoundException("Delete failed; user not found for userId: " + userId);
        }
    }

    @Override
    public boolean userExistsByEmail(String email) {
        if (!StringUtils.hasText(email)) {
            return false;
        }
        return userDao.findByEmail(email) != null;
    }

    // ---------- Validations ----------

    private void validateForCreate(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        if (!StringUtils.hasText(user.getName())) {
            throw new IllegalArgumentException("name cannot be empty");
        }
        validateEmail(user.getEmail());
        if (!StringUtils.hasText(user.getPassword())) {
            throw new IllegalArgumentException("password cannot be empty");
        }
        validateRole(user.getRole());
        // phone is optional; if present, you can add basic length/format check
        // locationId is optional (can be null)
    }

    private void validateForUpdate(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        if (user.getUserId() <= 0) {
            throw new IllegalArgumentException("userId must be positive");
        }
        if (!StringUtils.hasText(user.getName())) {
            throw new IllegalArgumentException("name cannot be empty");
        }
        validateEmail(user.getEmail());
        if (!StringUtils.hasText(user.getPassword())) {
            throw new IllegalArgumentException("password cannot be empty");
        }
        validateRole(user.getRole());
    }

    private void validateEmail(String email) {
        if (!StringUtils.hasText(email)) {
            throw new IllegalArgumentException("email cannot be empty");
        }
        if (!EMAIL_REGEX.matcher(email).matches()) {
            throw new IllegalArgumentException("Invalid email format: " + email);
        }
    }

    private void validateRole(String role) {
        if (!StringUtils.hasText(role)) {
            // DB default is Buyer; you can choose to allow null to trigger DB default
            throw new IllegalArgumentException("role cannot be empty");
        }
        String normalized = role.trim();
        if (!("Admin".equalsIgnoreCase(normalized)
                || "Seller".equalsIgnoreCase(normalized)
                || "Buyer".equalsIgnoreCase(normalized))) {
            throw new IllegalArgumentException("Invalid role: " + role + ". Allowed: Admin, Seller, Buyer");
        }
    }
    
    @Override
    public Map<String, Object> getUserWithLocation(int userId) {
        return userDao.getUserWithLocation(userId);
    }
}
