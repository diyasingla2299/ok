package com.ShopSphere.shop_sphere.model;

public class User {
	
	public User(int userId, String name, String email, String password, String phone, String role, Integer locationId) {
		this.userId = userId;
		this.name = name;
		this.email = email;
		this.password = password;
		this.phone = phone;
		this.role = role;
		this.locationId = locationId;
	}

	private int userId;
	private String name;
	private String email;
	private String password;
	private String phone;
	private String role;
	private Integer locationId;
	
	public User() {}

	public int getUserId() {
		return userId;
	}

	public String getName() {
		return name;
	}

	public String getEmail() {
		return email;
	}

	public String getPassword() {
		return password;
	}

	public String getPhone() {
		return phone;
	}

	public String getRole() {
		return role;
	}

	public Integer getLocationId() {
		return locationId;
	}

	public void setUserId(int userId) {
		this.userId = userId;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public void setLocationId(Integer locationId) {
		this.locationId = locationId;
	}

	@Override
	public String toString() {
		return "User [userId=" + userId + ", name=" + name + ", email=" + email + ", password=" + password + ", phone="
				+ phone + ", role=" + role + ", locationId=" + locationId + "]";
	}

}
