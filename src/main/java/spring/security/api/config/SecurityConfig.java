package spring.security.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true) // permite colocar as permissões por roles nos controllers
public class SecurityConfig {

    // role -> grupo de usuários ( perfil de usuáiro ) -> Master, frente de loja, vendedor
    // authority -> permissões -> cadastrar usuário, acessar tela de relatório

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            SenhaMasterAuthenticationProvider senhaMasterAuthenticationProvider,
            CustomAuthenticationProvider customAuthenticationProvider,
            CustomFilter customFilter) throws Exception {
        return http
                // Quando é uma API deve desabilitar o csrf
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(customizer -> {
                    customizer.requestMatchers("/public").permitAll(); // Permite o acesso a todos os requests para a rota /public
                    customizer.requestMatchers("/admin").hasRole( "ADMIN" );
                    customizer.anyRequest().authenticated(); // O anyRequests() deve ser chamado por último
                })
                .httpBasic(Customizer.withDefaults()) // Permite a autenticação com o header BASIC [user;senha em Base 64]
                .formLogin(Customizer.withDefaults()) // Permite utilizar o formulário padrão de login do Spring Security
                // Pode ser adicionado diversos providers
                .authenticationProvider( senhaMasterAuthenticationProvider )
                .authenticationProvider( customAuthenticationProvider )
                // O customFilter será chamado antes de UsernamePasswordAuthenticationFilter
                .addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // Quando é adicionado um authenticationProvider o UserDetailsService não é mais utilizado
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails commonUser = User.builder()
                .username("user")
                .password(passwordEncoder().encode("123"))
                .roles("USER")
                .build();

        UserDetails adminUser = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN", "USER" )
                .build();

        return new InMemoryUserDetailsManager( commonUser, adminUser ); // Utiliza os usuários em mémoria
    }

    // Encoder de senhas
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder( );
    }

    // Remove o prefixo "ROLE_"
    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults(){
        return new GrantedAuthorityDefaults("");
    }
}
