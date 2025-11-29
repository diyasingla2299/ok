package com.ShopSphere.shop_sphere.service;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.ShopSphere.shop_sphere.exception.BadRequestException;
import com.ShopSphere.shop_sphere.exception.DuplicateResourceException;
import com.ShopSphere.shop_sphere.exception.ResourceNotFoundException;
import com.ShopSphere.shop_sphere.model.Wishlist;
import com.ShopSphere.shop_sphere.repository.WishlistDao;

@Service
public class WishlistServiceImpl implements WishlistService {

    private final WishlistDao wishlistDao;

    public WishlistServiceImpl(WishlistDao wishlistDao) {
        this.wishlistDao = wishlistDao;
    }

    @Override
    public Wishlist createWishlist(int userId) {
        if (userId <= 0) {
            throw new BadRequestException("Invalid userId: " + userId);
        }

        if (wishlistDao.wishlistExistsForUser(userId)) {
            throw new DuplicateResourceException("Wishlist already exists for userId: " + userId);
        }

        int wishlistId = wishlistDao.createWishlist(userId);

        if (wishlistId <= 0) {
            throw new BadRequestException("Failed to create wishlist for userId: " + userId);
        }

        Wishlist created = wishlistDao.findById(wishlistId);
        if (created == null) {
            throw new ResourceNotFoundException("Wishlist created but not found for ID: " + wishlistId);
        }

        return created;
    }

    @Override
    public Wishlist getWishlistByUserId(int userId) {
        if (userId <= 0) {
            throw new BadRequestException("Invalid userId: " + userId);
        }

        Wishlist wishlist = wishlistDao.findByUserId(userId);
        if (wishlist == null) {
            throw new ResourceNotFoundException("No wishlist found for userId: " + userId);
        }
        return wishlist;
    }

    @Override
    public Wishlist getWishlistById(int wishlistId) {
        if (wishlistId <= 0) {
            throw new BadRequestException("Invalid wishlistId: " + wishlistId);
        }

        Wishlist wishlist = wishlistDao.findById(wishlistId);
        if (wishlist == null) {
            throw new ResourceNotFoundException("No wishlist found for wishlistId: " + wishlistId);
        }
        return wishlist;
    }

    @Override
    public List<Wishlist> getAllWishlists() {
        List<Wishlist> all = wishlistDao.getAllWishlists();
        return all == null ? List.of() : all;
    }

    @Override
    public void deleteWishlist(int wishlistId) {
        if (wishlistId <= 0) {
            throw new BadRequestException("Invalid wishlistId: " + wishlistId);
        }

        // This already throws ResourceNotFoundException if missing
        Wishlist w = getWishlistById(wishlistId);

        int rows = wishlistDao.deleteWishlist(w.getWishlistId());
        if (rows <= 0) {
            throw new BadRequestException("Failed to delete wishlistId: " + wishlistId);
        }
    }

    @Override
    public boolean wishlistExistsForUser(int userId) {
        if (userId <= 0) {
            throw new BadRequestException("Invalid userId: " + userId);
        }
        return wishlistDao.wishlistExistsForUser(userId);
    }

    @Override
    public boolean isWishlistEmpty(int wishlistId) {
        if (wishlistId <= 0) {
            throw new BadRequestException("Invalid wishlistId: " + wishlistId);
        }

        Wishlist w = getWishlistById(wishlistId);
        return wishlistDao.isWishlistEmpty(w.getWishlistId());
    }
    

    @Override
    public List<Map<String, Object>> getWishlistItems(int userId) {
        if (userId <= 0) {
            throw new BadRequestException("Invalid userId: " + userId);
        }

        List<Map<String, Object>> items = wishlistDao.getWishlistItems(userId);

        if (items == null || items.isEmpty()) {
            throw new ResourceNotFoundException("No wishlist items found for userId: " + userId);
        }

        return items;
    }
    

}
