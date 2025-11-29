package com.ShopSphere.shop_sphere.repository;

import java.util.List;
import java.util.Map;

import com.ShopSphere.shop_sphere.model.User;

public interface UserDao {
	
	int save(User user);
	User findById(int userId);
	User findByEmail(String email);
	List<User> findAll();
	int update(User user);
	int delete(int userID);
	int locationIdOfUser(int buyerId);
	
	Map<String, Object> getUserWithLocation(int userId);

}
