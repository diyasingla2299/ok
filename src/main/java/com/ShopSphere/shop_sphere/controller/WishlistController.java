package com.ShopSphere.shop_sphere.controller;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.ShopSphere.shop_sphere.dto.WishlistDto;
import com.ShopSphere.shop_sphere.exception.BadRequestException;
import com.ShopSphere.shop_sphere.exception.DuplicateResourceException;
import com.ShopSphere.shop_sphere.exception.ResourceNotFoundException;
import com.ShopSphere.shop_sphere.model.Wishlist;
import com.ShopSphere.shop_sphere.security.AllowedRoles;
import com.ShopSphere.shop_sphere.security.SecurityUtil;
import com.ShopSphere.shop_sphere.service.WishlistService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/wishlists")
public class WishlistController {

    private final WishlistService wishlistService;

    public WishlistController(WishlistService wishlistService) {
        this.wishlistService = wishlistService;
    }

    private WishlistDto entityToDto(Wishlist w) {
        WishlistDto dto = new WishlistDto();
        dto.setWishlistId(w.getWishlistId());
        dto.setUserId(w.getUserId());
        return dto;
    }

    // ---------------- Security Helpers ----------------
    private void validateUserOrAdmin(HttpServletRequest request, int userId) {
        int loggedUserId = SecurityUtil.getLoggedInUserId(request);
        if (!SecurityUtil.isAdmin(request) && loggedUserId != userId) {
            throw new SecurityException("Unauthorized: Cannot access another user's wishlist");
        }
    }

    // ---------------- CREATE ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @PostMapping("/{userId}")
    public ResponseEntity<?> createWishlist(@PathVariable int userId, HttpServletRequest request) {
        validateUserOrAdmin(request, userId);
        try {
            Wishlist w = wishlistService.createWishlist(userId);
            return ResponseEntity.status(HttpStatus.CREATED).body(entityToDto(w));
        } catch (DuplicateResourceException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
        } catch (BadRequestException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
        }
    }

    // ---------------- GET BY USER ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/user/{userId}")
    public ResponseEntity<?> getWishlistByUserId(@PathVariable int userId, HttpServletRequest request) {
        validateUserOrAdmin(request, userId);
        try {
            Wishlist w = wishlistService.getWishlistByUserId(userId);
            return ResponseEntity.ok(entityToDto(w));
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
        }
    }

    // ---------------- GET BY ID ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/{wishlistId}")
    public ResponseEntity<?> getWishlistById(@PathVariable int wishlistId, HttpServletRequest request) {
        try {
            Wishlist w = wishlistService.getWishlistById(wishlistId);
            validateUserOrAdmin(request, w.getUserId());
            return ResponseEntity.ok(entityToDto(w));
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
        }
    }

    // ---------------- FETCH ALL ----------------
    @AllowedRoles({"ADMIN"})
    @GetMapping
    public List<WishlistDto> getAllWishlists() {
        return wishlistService.getAllWishlists()
                .stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }

    // ---------------- DELETE ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @DeleteMapping("/{wishlistId}")
    public ResponseEntity<?> deleteWishlist(@PathVariable int wishlistId, HttpServletRequest request) {
        try {
            Wishlist w = wishlistService.getWishlistById(wishlistId);
            validateUserOrAdmin(request, w.getUserId());
            wishlistService.deleteWishlist(wishlistId);
            return ResponseEntity.ok("Wishlist deleted successfully");
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
        }
    }

    // ---------------- EXISTS ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/exists/{userId}")
    public ResponseEntity<?> wishlistExistsForUser(@PathVariable int userId, HttpServletRequest request) {
        validateUserOrAdmin(request, userId);
        boolean exists = wishlistService.wishlistExistsForUser(userId);
        return ResponseEntity.ok(exists);
    }

    // ---------------- EMPTY CHECK ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/empty/{wishlistId}")
    public ResponseEntity<?> isWishlistEmpty(@PathVariable int wishlistId, HttpServletRequest request) {
        try {
            Wishlist w = wishlistService.getWishlistById(wishlistId);
            validateUserOrAdmin(request, w.getUserId());
            boolean empty = wishlistService.isWishlistEmpty(wishlistId);
            return ResponseEntity.ok(empty);
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
        }
    }

    // ---------------- GET ITEMS ----------------
    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/items/{userId}")
    public ResponseEntity<?> getWishlistItems(@PathVariable int userId, HttpServletRequest request) {
        validateUserOrAdmin(request, userId);
        try {
            List<Map<String, Object>> items = wishlistService.getWishlistItems(userId);
            if (items.isEmpty()) {
                throw new ResourceNotFoundException("No wishlist items found for userId: " + userId);
            }
            return ResponseEntity.ok(items);
        } catch (ResourceNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
        }
    }
}
