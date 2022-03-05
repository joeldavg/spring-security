package com.amigoscode.security;

import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.amigoscode.auth.ApplicationUserService;

import lombok.RequiredArgsConstructor;

import static com.amigoscode.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import static com.amigoscode.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
//			.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//			.and()
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
				.loginPage("/login").permitAll()
				.defaultSuccessUrl("/courses", true)
				.passwordParameter("password") // if we like to change it
				.usernameParameter("username")
			.and()
			.rememberMe()
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
				.key("SOMETHINGVERYSECURED")
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login"); // default 2 weeks
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		
		return provider;
	}

}