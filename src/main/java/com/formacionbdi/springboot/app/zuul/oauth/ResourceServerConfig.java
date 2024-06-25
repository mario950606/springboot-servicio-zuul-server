package com.formacionbdi.springboot.app.zuul.oauth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@RefreshScope            //Para actualizar parametros sin necesidad de reiniciar
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

	@Value("${config.security.oauth.jwt.key}")
	private String jwtKey;
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception { //Proteger endpoint
		http.authorizeRequests().antMatchers("/api/security/oauth/**").permitAll()    //todo el mundo puede autenticarse
		.antMatchers(HttpMethod.GET, "/api/productos/listar", "/api/items/listar", "/api/usuarios/usuarios").permitAll()
		.antMatchers(HttpMethod.GET, "/api/productos/ver/{id}","/api/items/ver/{id}/cantidad/{cantidad}"
				,"/api/usuarios/usuarios/{id}").hasAnyRole("ADMIN","USER")
		.antMatchers("/api/productos/**", "/api/items/**", "/api/usuarios/**").hasRole("ADMIN")
		.anyRequest().authenticated()
		.and().cors().configurationSource(corsConfigurationSource()); //cualquier ruta que no haya sido identificada requiere autenticacion
		/*.antMatchers(HttpMethod.POST, "/api/productos/crear","/api/items/crear").hasRole("ADMIN")
		.antMatchers(HttpMethod.PUT, "/api/productos/editar/{id}","/api/items/editar/{id}", "/api/usuarios/usuarios/{id}").hasRole("ADMIN")
		.antMatchers(HttpMethod.DELETE, "/api/productos/eliminar/{id}","/api/items/eliminar/{id}", "/api/usuarios/usuarios/{id}").hasRole("ADMIN");*/ 
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {   //configura el spring security del CORS A TODAS LAS RUTAS
		CorsConfiguration corsConfig= new CorsConfiguration();
		corsConfig.setAllowedOrigins(Arrays.asList("*"));   //si fuera angular http://localhost:4200//add es para uno, set es para un listado
		corsConfig.setAllowedMethods(Arrays.asList("POST","GET","PUT","DELETE", "OPTIONS"));
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization","Content-Type"));
		
		UrlBasedCorsConfigurationSource source= new UrlBasedCorsConfigurationSource(); //pasar la configuracion a los endpoint, rutas URL
		source.registerCorsConfiguration("/**", corsConfig);
		return source;
	}
	
	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter(){  //CONFIGURAMOS PARA QUE SE APLIQUE EN TODO SOLO SE HACE CUANDO INTERACTUA CON OTROS, ES OPCIONAL
		FilterRegistrationBean<CorsFilter> bean= new FilterRegistrationBean<CorsFilter>(new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}
	
	

	@Bean
	public JwtTokenStore tokenStore() {  //crea el token y para poder almacenarlo

		return new JwtTokenStore(accessTokenConverter());
	}


	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {

		
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setSigningKey(jwtKey);
		return tokenConverter;
	}
	
	
}
