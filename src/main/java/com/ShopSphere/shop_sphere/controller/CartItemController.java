package com.ShopSphere.shop_sphere.controller;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.*;

import com.ShopSphere.shop_sphere.dto.CartItemDto;
import com.ShopSphere.shop_sphere.model.CartItem;
import com.ShopSphere.shop_sphere.model.Cart;
import com.ShopSphere.shop_sphere.security.AllowedRoles;
import com.ShopSphere.shop_sphere.security.SecurityUtil;
import com.ShopSphere.shop_sphere.service.CartItemService;
import com.ShopSphere.shop_sphere.service.CartService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/cart-items")
public class CartItemController {

    private final CartItemService cartItemService;
    private final CartService cartService;

    public CartItemController(CartItemService cartItemService, CartService cartService) {
        this.cartItemService = cartItemService;
        this.cartService = cartService;
    }

    private CartItem dtoToEntity(CartItemDto dto) {
        CartItem item = new CartItem();
        item.setCartItemsId(dto.getCartItemId());
        item.setCartId(dto.getCartId());
        item.setProductId(dto.getProductId());
        item.setQuantity(dto.getQuantity());
        return item;
    }

    private CartItemDto entityToDto(CartItem item) {
        CartItemDto dto = new CartItemDto();
        dto.setCartItemId(item.getCartItemsId());
        dto.setCartId(item.getCartId());
        dto.setProductId(item.getProductId());
        dto.setQuantity(item.getQuantity());
        return dto;
    }

    // ---------------- Security Helper ----------------

    private void validateCartOwner(int cartId, HttpServletRequest request) {
        Cart cart = cartService.getCartById(cartId);
        int loggedUserId = SecurityUtil.getLoggedInUserId(request);
        if (!SecurityUtil.isAdmin(request) && loggedUserId != cart.getUserId()) {
            throw new SecurityException("Unauthorized: Cannot access or modify another user's cart");
        }
    }

    // ---------------- APIs ----------------

    @AllowedRoles({"BUYER"})
    @PostMapping
    public CartItemDto addItem(@RequestBody CartItemDto dto, HttpServletRequest request) {
        validateCartOwner(dto.getCartId(), request);
        CartItem saved = cartItemService.addItem(dtoToEntity(dto));
        return entityToDto(saved);
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/cart/{cartId}")
    public List<CartItemDto> getItemsByCartId(@PathVariable int cartId, HttpServletRequest request) {
        validateCartOwner(cartId, request);
        return cartItemService.getItemsByCartId(cartId)
                .stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/single/{cartId}")
    public CartItemDto findItemByCartId(@PathVariable int cartId, HttpServletRequest request) {
        validateCartOwner(cartId, request);
        Optional<CartItem> item = cartItemService.findItemByCartId(cartId);
        return item.map(this::entityToDto)
                .orElseThrow(() -> new RuntimeException("Item not found"));
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @PutMapping("/{cartItemId}/quantity/{quantity}")
    public CartItemDto updateItemQuantity(@PathVariable int cartItemId,
                                          @PathVariable int quantity,
                                          HttpServletRequest request) {
        CartItem item = cartItemService.getItemById(cartItemId);
        validateCartOwner(item.getCartId(), request);
        return entityToDto(cartItemService.updateItemQuantity(cartItemId, quantity));
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @DeleteMapping("/{cartItemId}")
    public String deleteItem(@PathVariable int cartItemId, HttpServletRequest request) {
        CartItem item = cartItemService.getItemById(cartItemId);
        validateCartOwner(item.getCartId(), request);
        cartItemService.deleteItem(cartItemId);
        return "Cart item deleted successfully";
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/total/{cartId}")
    public double calculateTotalAmount(@PathVariable int cartId, HttpServletRequest request) {
        validateCartOwner(cartId, request);
        return cartItemService.calculateTotalAmount(cartId);
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/exists/{cartId}/{productId}")
    public boolean existsInCart(@PathVariable int cartId,
                                @PathVariable int productId,
                                HttpServletRequest request) {
        validateCartOwner(cartId, request);
        return cartItemService.existsInCart(cartId, productId);
    }
}
