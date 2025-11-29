
package com.ShopSphere.shop_sphere.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class UserDto {

    public UserDto(
            Integer userId,
            @NotBlank(message = "Name is required")
            @Size(min = 2, max = 60, message = "Name must be between 2 and 60 characters")
            String name,
            @NotBlank(message = "Email is required")
            @Email(message = "Email must be valid")
            @Size(max = 100, message = "Email must be at most 100 characters")
            String email,
            @Size(max = 20, message = "Phone must be at most 20 characters")
            String phone,
            @NotNull(message = "Role is required")
            @Pattern(regexp = "Admin|Seller|Buyer", message = "Role must be Admin, Seller, or Buyer")
            String role,
            Integer locationId
    ) {
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.phone = phone;
        this.role = role;
        this.locationId = locationId;
    }

    public UserDto() {}

    private Integer userId;

    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 60, message = "Name must be between 2 and 60 characters")
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Size(max = 100, message = "Email must be at most 100 characters")
    private String email;

    @Size(max = 20, message = "Phone must be at most 20 characters")
    private String phone; // nullable in DB

    @NotNull(message = "Role is required")
    @Pattern(regexp = "Admin|Seller|Buyer", message = "Role must be Admin, Seller, or Buyer")
    private String role; // enum values: Admin, Seller, Buyer

    private Integer locationId; // nullable in DB

    // Getters
    public Integer getUserId() { return userId; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public String getPhone() { return phone; }
    public String getRole() { return role; }
    public Integer getLocationId() { return locationId; }

    // Setters
    public void setUserId(Integer userId) { this.userId = userId; }
    public void setName(String name) { this.name = name; }
    public void setEmail(String email) { this.email = email; }
    public void setPhone(String phone) { this.phone = phone; }
    public void setRole(String role) { this.role = role; }
    public void setLocationId(Integer locationId) { this.locationId = locationId; }

    @Override
    public String toString() {
        return "UserDto [userId=" + userId
                + ", name=" + name
                + ", email=" + email
                + ", phone=" + phone
                + ", role=" + role
                + ", locationId=" + locationId + "]";
    }
}
