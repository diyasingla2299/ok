package com.ShopSphere.shop_sphere.service;

import org.springframework.stereotype.Service;

import com.ShopSphere.shop_sphere.repository.LocationDao;
import com.ShopSphere.shop_sphere.repository.ProductDao;
import com.ShopSphere.shop_sphere.repository.UserDao;

@Service
public class DeliveryService {

	
	private final LocationDao locationDao;
	private final UserDao userDao;
	private final ProductDao productDao;
	
	public DeliveryService(LocationDao locationDao, 
			UserDao userDao, ProductDao productDao)
	{
		this.locationDao = locationDao;
		this.productDao = productDao;
		this.userDao = userDao;
	}
	
	public int calculateDeliveryDays(int buyerId, int productId) {
		int buyerLocationId = userDao.locationIdOfUser(buyerId);
		int buyerHub = locationDao.getHubValue(buyerLocationId);
		int sellerId = productDao.getSellerIdByProductId(productId);
		int sellerLocationId = userDao.locationIdOfUser(sellerId);
		int sellerHub = locationDao.getHubValue(sellerLocationId);
		int diff = Math.abs(buyerHub - sellerHub );
		return diff / 20;
	}
}
