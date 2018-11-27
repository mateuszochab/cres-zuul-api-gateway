package com.ochabmateusz.cres.creszuulapigateway.securityconfig;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ochabmateusz.cres.cresconfigserver.security.JwtConfig;
@Configuration
@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

	
	@Autowired
	private JwtConfig jwtConfig;
	
	@Autowired
	private CorsFilter corsfilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	
		http
				.csrf().disable()
				// make sure we use stateless session; session won't be used to store user's state.
					.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				// handle an authorized attempts 
					.exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
				.and()
				 // Add a filter to validate the tokens with every request
					.addFilterBefore(corsfilter, ChannelProcessingFilter.class)
					.addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
					// authorization requests config
				.authorizeRequests()
				  // allow all who are accessing "auth" service
					.antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
					 // must be an admin if trying to access admin area (authentication is also required here)
					//.antMatchers("/signup" + "/admin/**").hasRole("admin")
					//.antMatchers("/admin").hasRole("admin")
					.antMatchers("/feedback").hasRole("free")
					.antMatchers("/register").permitAll()
					.antMatchers("/login").permitAll()
					 // Any other request must be authenticated
					.anyRequest().authenticated();
		
		
		
	}
	
	
	@Bean
  	public JwtConfig jwtConfig() {
    	   return new JwtConfig();
  	}
	
	
	

}
