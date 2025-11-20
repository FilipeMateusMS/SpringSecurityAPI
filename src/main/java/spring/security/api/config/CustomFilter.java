package spring.security.api.config;

import spring.security.api.domain.security.CustomAuthentication;
import spring.security.api.domain.security.IdentificacaoUsuario;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class CustomFilter extends OncePerRequestFilter
{
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException
    {

        String secretHeader = request.getHeader("x-secret"); // Obter o header x-secret

        if(secretHeader != null){
            if(secretHeader.equals("secr3t")){ // Se existir e o valor for secr3t
                var identificacaoUsuario = new IdentificacaoUsuario(
                        "id-secret",
                        "Muito Secreto",
                        "x-secret",
                        List.of("USER")
                );
                Authentication authentication = new CustomAuthentication( identificacaoUsuario );

                SecurityContext securityContext = SecurityContextHolder.getContext();
                securityContext.setAuthentication( authentication ); // Altera para autenticado
            }
        }

        filterChain.doFilter(request, response); // segue para o próximo fluxo, deve chamar esse método
    }
}
