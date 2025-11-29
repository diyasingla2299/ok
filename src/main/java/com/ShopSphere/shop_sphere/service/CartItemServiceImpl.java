package com.ShopSphere.shop_sphere.service;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.ShopSphere.shop_sphere.exception.ResourceNotFoundException;
import com.ShopSphere.shop_sphere.exception.ValidationException;
import com.ShopSphere.shop_sphere.model.CartItem;
import com.ShopSphere.shop_sphere.repository.CartItemDao;

@Service
public class CartItemServiceImpl implements CartItemService {

    private final CartItemDao cartItemDao;

    public CartItemServiceImpl(CartItemDao cartItemDao) {
        this.cartItemDao = cartItemDao;
    }

    @Override
    public CartItem addItem(CartItem item) {

        if (item.getQuantity() <= 0) {
            throw new ValidationException("Quantity must be greater than 0");
        }

        // IF ITEM EXISTS → UPDATE QUANTITY
        if (cartItemDao.existsInCart(item.getCartId(), item.getProductId())) {

            CartItem existing = cartItemDao.findByProductAndCart(item.getCartId(), item.getProductId())
                    .orElseThrow(() -> new ResourceNotFoundException("Existing cart item not found"));

            int newQty = existing.getQuantity() + item.getQuantity();
            cartItemDao.updateItemQuantity(existing.getCartItemsId(), newQty);

            return cartItemDao.findByProductAndCart(item.getCartId(), item.getProductId()).get();
        }

        // ELSE → ADD NEW ITEM
        return cartItemDao.addItem(item);
    }

    @Override
    public Optional<CartItem> findItemByCartId(int cartId) {
        return cartItemDao.findByCartId(cartId);
    }

    @Override
    public List<CartItem> getItemsByCartId(int cartId) {
        return cartItemDao.findAllByCartId(cartId);
    }

    @Override
    public CartItem updateItemQuantity(int cartItemId, int quantity) {
        int updated = cartItemDao.updateItemQuantity(cartItemId, quantity);

        if (updated <= 0) {
            throw new ResourceNotFoundException("Cart item not found with id: " + cartItemId);
        }

        return cartItemDao.findByCartId(cartItemId)
                .orElseThrow(() -> new ResourceNotFoundException("Cart item not found"));
    }

    @Override
    public void deleteItem(int cartItemId) {
        int rows = cartItemDao.deleteItem(cartItemId);

        if (rows <= 0) {
            throw new ResourceNotFoundException("Cart item not found with id: " + cartItemId);
        }
    }

    @Override
    public void deleteItemByProductId(int cartId, int productId) {
        int rows = cartItemDao.deleteItemByProductId(cartId, productId);

        if (rows <= 0) {
            throw new ResourceNotFoundException("No cart item found for product: " + productId);
        }
    }

    @Override
    public double calculateTotalAmount(int cartId) {
        return cartItemDao.calculateTotalAmount(cartId);
    }

    @Override
    public boolean existsInCart(int cartId, int productId) {
        return cartItemDao.existsInCart(cartId, productId);
    }

    @Override
    public CartItem getItemById(int cartItemId) {
        return cartItemDao.findById(cartItemId)
                .orElseThrow(() -> new ResourceNotFoundException("Cart item not found with id: " + cartItemId));
    }
}
