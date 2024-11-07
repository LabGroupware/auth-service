package org.cresplanex.account.oauth.service;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.WebApplicationContext;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.context.WebEngineContext;
import org.thymeleaf.context.WebExpressionContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.util.Map;

@Service
public class HtmlRenderingService {

    @Autowired
    private SpringTemplateEngine templateEngine;

    public String renderHtml(
            HttpServletRequest request,
            HttpServletResponse response,
            String templateName,
            Map<String, Object> variables
    ) {
        var application = JakartaServletWebApplication.buildApplication(request.getServletContext());
        var exchange = application.buildExchange(request, response);
        WebContext context = new WebContext(exchange, request.getLocale(), variables);
        return templateEngine.process(templateName, context);
    }
}
