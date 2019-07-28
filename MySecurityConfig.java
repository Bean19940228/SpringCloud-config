package com.gao.SpringBootMain.config;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 自定义Spring Security配置类
 * @author 小黄豆
 *
 */

//此注解指明这是一个Security配置类并启动安全配置
//此注解已经包含@Configuration,所以不必再写
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter
{
	//定制请求的授权规则
	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		//允许所有人访问localhost:8888/
		//只有以Fred身份登陆才能访问localhost:8888/hello和
		//localhost:8888/api,如果不是Fred访问则显示Access Denied
		http.authorizeRequests().antMatchers("/").permitAll()
				.antMatchers("/hello").hasRole("Admin")
				.antMatchers("/api").hasRole("Fred");
		
		//开启自动配置的登陆功能
		//来到/login登陆页(spring security自动生成的页面)
		//如果登陆失败则重定向到/login?error表示登陆失败
		//用户名密码在下一个方法中配置
		//可以自定义登录页http.formLogin().loginPage("/logintest")
		//但如果自定义了登陆页,则默认提供的logout也会访问不到,
		//需要自己写logout
		http.formLogin();
		
		//开启自动配置的注销功能
		//访问/logout,清空session
		//注销成功会默认自动回到login
		//可以手动指定注销完前往的页面logoutSuccessUrl()
		http.logout().logoutSuccessUrl("/rest");
		
		//开启记住我功能
		//会在login界面加一个勾选框
		//底层实际是给浏览器发了一个2周后过期的cookie
		//点击/logout后会清除此cookie
		http.rememberMe();
	}
	
	//定义认证规则
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception
	{
		//这种定制方法是保存到内存中,正常情况应该是保存到数据库
		//注意这里必须使用passwordEncoder,这是新版Spring Security的要求
		auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("Gaoyuchen").password(new BCryptPasswordEncoder().encode("1823")).roles("Fred","Admin").and().withUser("Gigi")
				.password(new BCryptPasswordEncoder().encode("4527")).roles("Admin");
	}
	
}
