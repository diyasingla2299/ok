package com.ShopSphere.shop_sphere.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.*;

import com.ShopSphere.shop_sphere.dto.WishlistItemDto;
import com.ShopSphere.shop_sphere.model.WishlistItem;
import com.ShopSphere.shop_sphere.security.AllowedRoles;
import com.ShopSphere.shop_sphere.security.SecurityUtil;
import com.ShopSphere.shop_sphere.service.WishlistItemService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/wishlist-items")
public class WishlistItemController {

    private final WishlistItemService wishlistItemService;

    public WishlistItemController(WishlistItemService wishlistItemService) {
        this.wishlistItemService = wishlistItemService;
    }

    private WishlistItem dtoToEntity(WishlistItemDto dto) {
        WishlistItem wi = new WishlistItem();
       // wi.setWishlistItemsId(dto.getWishlistItemsId());
        wi.setWishlistId(dto.getWishlistId());
        wi.setProductId(dto.getProductId());
        return wi;
    }

    private WishlistItemDto entityToDto(WishlistItem wi) {
        WishlistItemDto dto = new WishlistItemDto();
        dto.setWishlistItemsId(wi.getWishlistItemsId());
        dto.setWishlistId(wi.getWishlistId());
        dto.setProductId(wi.getProductId());
        return dto;
    }

    // ---------------- Security Helper ----------------
    private void validateUserOrAdmin(HttpServletRequest request, int wishlistId) {
        int loggedUserId = SecurityUtil.getLoggedInUserId(request);
        int ownerId = wishlistItemService.getWishlistOwnerId(wishlistId); // implement in service
        if (!SecurityUtil.isAdmin(request) && loggedUserId != ownerId) {
            throw new SecurityException("Unauthorized: Cannot access another user's wishlist items");
        }
    }

    // ---------------- API Endpoints ----------------

    @AllowedRoles({"BUYER", "ADMIN"})
    @PostMapping
    public int addItem(@RequestBody WishlistItemDto dto, HttpServletRequest request) {
        validateUserOrAdmin(request, dto.getWishlistId());
        return wishlistItemService.addItemToWishlist(dtoToEntity(dto));
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @GetMapping("/wishlist/{wishlistId}")
    public List<WishlistItemDto> getItemsByWishlist(@PathVariable int wishlistId, HttpServletRequest request) {
        validateUserOrAdmin(request, wishlistId);
        return wishlistItemService.getItemsByWishlistId(wishlistId)
                .stream()
                .map(this::entityToDto)
                .collect(Collectors.toList());
    }

    @AllowedRoles({"BUYER", "ADMIN"})
    @DeleteMapping("/{wishlistItemId}")
    public String deleteItem(@PathVariable int wishlistItemId, HttpServletRequest request) {
        int wishlistId = wishlistItemService.getWishlistIdByItem(wishlistItemId); // implement in service
        validateUserOrAdmin(request, wishlistId);
        wishlistItemService.deleteItem(wishlistItemId);
        return "Wishlist item deleted successfully";
    }
}
