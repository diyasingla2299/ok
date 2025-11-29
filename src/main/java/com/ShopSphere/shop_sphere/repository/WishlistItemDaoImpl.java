package com.ShopSphere.shop_sphere.repository;

import com.ShopSphere.shop_sphere.model.WishlistItem;
import com.ShopSphere.shop_sphere.util.WishlistItemRowMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;

@Repository
public class WishlistItemDaoImpl implements WishlistItemDao {

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public WishlistItemDaoImpl(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // -------- SQL --------
    private static final String INSERT_SQL =
            "INSERT INTO wishlists_items (wishlist_id, product_id) VALUES (?, ?)";

    private static final String SELECT_BY_WISHLIST_SQL =
            "SELECT wishlist_items_id, wishlist_id, product_id " +
            "FROM wishlists_items WHERE wishlist_id = ? ORDER BY wishlist_items_id";

    private static final String DELETE_SQL =
            "DELETE FROM wishlists_items WHERE wishlist_items_id = ?";

    // -------- DAO Methods --------

    /**
     * Adds a product to a wishlist and returns the generated wishlist_items_id.
     * Returns 0 if the item already exists (DuplicateKeyException due to a unique constraint) or insertion failed.
     */
    @Override
    public int addItem(WishlistItem wishlistItem) {
        KeyHolder keyHolder = new GeneratedKeyHolder();
        try {
            int affected = jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(INSERT_SQL, Statement.RETURN_GENERATED_KEYS);
                ps.setInt(1, wishlistItem.getWishlistId());
                ps.setInt(2, wishlistItem.getProductId());
                return ps;
            }, keyHolder);

            if (affected > 0 && keyHolder.getKey() != null) {
                int id = keyHolder.getKey().intValue();
                wishlistItem.setWishlistItemsId(id);
                return id;
            }
        } catch (DuplicateKeyException dke) {
            // If you enforce (wishlist_id, product_id) uniqueness, signal "already exists"
            return 0;
        }
        return 0;
    }

    @Override
    public List<WishlistItem> findByWishlistId(int wishlistId) {
        return jdbcTemplate.query(SELECT_BY_WISHLIST_SQL, new WishlistItemRowMapper(), wishlistId);
    }

    @Override
    public int deleteItem(int wishlistItemId) {
        return jdbcTemplate.update(DELETE_SQL, wishlistItemId);
    }
    
    @Override
    public int getWishlistIdByItem(int wishlistItemId) {
        String sql = "SELECT wishlist_id FROM wishlist_items WHERE wishlist_item_id = ?";
        return jdbcTemplate.queryForObject(sql, Integer.class, wishlistItemId);
    }
    
    @Override
    public int getWishlistOwnerId(int wishlistId) {
        String sql = "SELECT user_id FROM wishlists WHERE wishlist_id = ?";
        return jdbcTemplate.queryForObject(sql, Integer.class, wishlistId);
    }
}