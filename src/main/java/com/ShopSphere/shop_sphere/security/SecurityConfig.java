package com.ShopSphere.shop_sphere.security;
 
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
 
@Configuration
public class SecurityConfig {
 
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter(JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(filter);
        reg.addUrlPatterns("/api/*");
        reg.setOrder(1);
        return reg;
    }
 
//    @Bean
//    public FilterRegistrationBean<RoleAuthorizationFilter> roleFilter(RoleAuthorizationFilter filter) {
//        FilterRegistrationBean<RoleAuthorizationFilter> reg = new FilterRegistrationBean<>();
//        reg.setFilter(filter);
//        reg.addUrlPatterns("/api/*");
//        reg.setOrder(2);
//        return reg;
//    }
    
    
}
 