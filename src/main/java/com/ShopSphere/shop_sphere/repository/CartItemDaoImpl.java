package com.ShopSphere.shop_sphere.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.ShopSphere.shop_sphere.model.CartItem;
import com.ShopSphere.shop_sphere.util.CartItemRowMapper;

@Repository
public class CartItemDaoImpl implements CartItemDao {

    private final JdbcTemplate jdbcTemplate;

    public CartItemDaoImpl(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    private RowMapper<CartItem> cartItemMapper = new RowMapper<CartItem>() {
        @Override
        public CartItem mapRow(ResultSet rs, int rowNum) throws SQLException {
            CartItem item = new CartItem();
            item.setCartItemsId(rs.getInt("cart_item_id"));
            item.setCartId(rs.getInt("cart_id"));
            item.setProductId(rs.getInt("product_id"));
            item.setQuantity(rs.getInt("quantity"));
            return item;
        }
    };

    @Override
    public CartItem addItem(CartItem item) {
        String sql = "INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, item.getCartId(), item.getProductId(), item.getQuantity());

        // return saved item
        return findByProductAndCart(item.getCartId(), item.getProductId()).get();
    }

    @Override
    public Optional<CartItem> findByCartId(int cartId) {
        String sql = "SELECT * FROM cart_items WHERE cart_id = ? LIMIT 1";
        try {
            return Optional.of(jdbcTemplate.queryForObject(sql, cartItemMapper, cartId));
        } catch (EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<CartItem> findByProductAndCart(int cartId, int productId) {
        String sql = "SELECT * FROM cart_items WHERE cart_id = ? AND product_id = ?";
        try {
            return Optional.of(jdbcTemplate.queryForObject(sql, cartItemMapper, cartId, productId));
        } catch (EmptyResultDataAccessException ex) {
            return Optional.empty();
        }
    }

    @Override
    public boolean existsInCart(int cartId, int productId) {
        String sql = "SELECT COUNT(*) FROM cart_items WHERE cart_id = ? AND product_id = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, cartId, productId);
        return count != null && count > 0;
    }

    @Override
    public List<CartItem> findAllByCartId(int cartId) {
        String sql = "SELECT * FROM cart_items WHERE cart_id = ?";
        return jdbcTemplate.query(sql, cartItemMapper, cartId);
    }

    @Override
    public int updateItemQuantity(int cartItemId, int quantity) {
        String sql = "UPDATE cart_items SET quantity = ? WHERE cart_item_id = ?";
        return jdbcTemplate.update(sql, quantity, cartItemId);
    }

    @Override
    public int deleteItem(int cartItemId) {
        String sql = "DELETE FROM cart_items WHERE cart_item_id = ?";
        return jdbcTemplate.update(sql, cartItemId);
    }

    @Override
    public int deleteItemByProductId(int cartId, int productId) {
        String sql = "DELETE FROM cart_items WHERE cart_id = ? AND product_id = ?";
        return jdbcTemplate.update(sql, cartId, productId);
    }

    @Override
    public double calculateTotalAmount(int cartId) {
        String sql = """
            SELECT SUM(ci.quantity * p.price) AS total
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.product_id
            WHERE ci.cart_id = ?
        """;

        Double total = jdbcTemplate.queryForObject(sql, Double.class, cartId);
        return total != null ? total : 0.0;
    }
    
    public Optional<CartItem> findById(int cartItemId) {
        String sql = "SELECT * FROM cart_items WHERE cart_item_id = ?";
        try {
            CartItem item = jdbcTemplate.queryForObject(sql,new  CartItemRowMapper(), cartItemId);
            return Optional.ofNullable(item);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
