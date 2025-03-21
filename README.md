# AspNetCore.Authentication.Basic
Easy to use and very light weight Microsoft style Basic Scheme Authentication Implementation for ASP.NET Core.

## This repository was moved to https://codeberg.org/mgernand/AspNetCore.Authentication.Basic

<br/> 

## Installing
This library is published on NuGet. So the NuGet package can be installed directly to your project if you wish to use it without making any custom changes to the code.

Download directly from below link.
Package link - [MadEyeMatt.AspNetCore.Authentication.Basic](https://www.nuget.org/packages/MadEyeMatt.AspNetCore.Authentication.Basic). 

Or by running the below command on your project.

```
PM> Install-Package MadEyeMatt.AspNetCore.Authentication.Basic
```

<br/> 

## Example Usage

Samples are available under [samples directory](samples).

Setting it up is quite simple. You will need basic working knowledge of ASP.NET Core 2.0 or newer to get started using this library.

There are 3 different ways of using this library to do it's job. All ways can be mixed if required.  
1. Using the implementation of *IBasicUserAuthenticationService*  
2. Using *BasicOptions.Events* (OnValidateCredentials delegate) which is same approach you will find on Microsoft's authentication libraries
3. Using an implementation of *IBasicUserAuthenticationServiceFactory* that is registered in the *IServiceCollection*

Notes:
- It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
- If an implementation of IBasicUserAuthenticationService interface is used as well as BasicOptions.Events.OnValidateCredentials delegate is also set then this delegate will be used first.
- If an implementation of IBasicUserAuthenticationServiceFactory interface is registered in the IServiceCollection the IBasicUserValidationService instances are tried to be created using the factory, 
  but if no instance is returned by the factory the fallback is to use the configured IApiKeyProvider implementation type.

**Always use HTTPS (SSL Certificate) protocol in production when using basic authentication.**

#### Configuration

```C#
using AspNetCore.Authentication.Basic;

public class Startup
{
	public void ConfigureServices(IServiceCollection services)
	{
		// It requires Realm to be set in the options if SuppressWWWAuthenticateHeader is not set.
		// If an implementation of IBasicUserAuthenticationService interface is used as well as options.Events.OnValidateCredentials delegate is also set then this delegate will be used first.
		
		services.AddAuthentication(BasicDefaults.AuthenticationScheme)

			// The below AddBasic without type parameter will require options.Events.OnValidateCredentials delegete to be set.
			//.AddBasic(options => { options.Realm = "My App"; });

			// The below AddBasic with type parameter will add the BasicUserAuthenticationService to the dependency container. 
			.AddBasic<BasicUserAuthenticationService>(options => { options.Realm = "My App"; });

		services.AddControllers();

		//// By default, authentication is not challenged for every request which is ASP.NET Core's default intended behaviour.
		//// So to challenge authentication for every requests please use below FallbackPolicy option.
		//services.AddAuthorization(options =>
		//{
		//	options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
		//});
	}

	public void Configure(IApplicationBuilder app, IHostingEnvironment env)
	{
		app.UseHttpsRedirection();

		// The below order of pipeline chain is important!
		app.UseRouting();

		app.UseAuthentication();
		app.UseAuthorization();

		app.UseEndpoints(endpoints =>
		{
			endpoints.MapControllers();
		});
	}
}
```

#### BasicUserAuthenticationService.cs
```C#
using AspNetCore.Authentication.Basic;

public class BasicUserAuthenticationService : IBasicUserAuthenticationService
{
	private readonly ILogger<BasicUserAuthenticationService> _logger;
	private readonly IUserRepository _userRepository;

	public BasicUserAuthenticationService(ILogger<BasicUserAuthenticationService> logger, IUserRepository userRepository)
	{
		_logger = logger;
		_userRepository = userRepository;
	}

	public async Task<IBasicUser> AuthenticateAsync(string username, string password)
	{
		try
		{
			// NOTE: DO NOT USE THIS IMPLEMENTATION. THIS IS FOR DEMO PURPOSE ONLY
			// Write your implementation here and return true or false depending on the validation.
			var user = await _userRepository.GetUserByUsername(username);
			var isValid = user != null && user.Password == password;
			return isValid ? new BasicUser(username) : null;
		}
		catch (Exception e)
		{
			_logger.LogError(e, e.Message);
			throw;
		}
	}
}
```

#### BasicUser
```C#
using AspNetCore.Authentication.Basic;

public class BasicUser : IBasicUser 
{
	public BasicUser(string userName, List<Claim> claims = null)
	{
		UserName = userName;
		Claims = claims ?? new List<Claim>();
	}

	public string UserName { get; }
	public IReadOnlyCollection<Claim> Claims { get; }
}
```

<br/>
<br/>

## Configuration (BasicOptions)

### Realm
Required to be set if SuppressWWWAuthenticateHeader is not set to true. It is used with WWW-Authenticate response header when challenging un-authenticated requests.  
   
### SuppressWWWAuthenticateHeader
Default value is false.  
If set to true, it will NOT return WWW-Authenticate response header when challenging un-authenticated requests.  
If set to false, it will return WWW-Authenticate response header when challenging un-authenticated requests.

### IgnoreAuthenticationIfAllowAnonymous (available on ASP.NET Core 3.0 onwards)
Default value is false.  
If set to true, it checks if AllowAnonymous filter on controller action or metadata on the endpoint which, if found, it does not try to authenticate the request.

### Events
The object provided by the application to process events raised by the basic authentication middleware.  
The application may implement the interface fully, or it may create an instance of BasicEvents and assign delegates only to the events it wants to process.
- #### OnValidateCredentials
	A delegate assigned to this property will be invoked just before validating credentials.  
	You must provide a delegate for this property for authentication to occur.  
	In your delegate you should either call context.ValidationSucceeded() which will handle construction of authentication claims principal from the user details which will be assiged the context.Principal property and calls context.Success(), or construct an authentication claims principal from the user details and assign it to the context.Principal property and finally call context.Success() method.  
	If only context.Principal property set without calling context.Success() method then, Success() method is automaticalled called.

- #### OnAuthenticationSucceeded  
	A delegate assigned to this property will be invoked when the authentication succeeds. It will not be called if OnValidateCredentials delegate is assigned.  
	It can be used for adding claims, headers, etc to the response.

- #### OnAuthenticationFailed  
	A delegate assigned to this property will be invoked when any unexpected exception is thrown within the library.

- #### OnHandleChallenge  
	A delegate assigned to this property will be invoked before a challenge is sent back to the caller when handling unauthorized response.  
	Only use this if you know what you are doing and if you want to use custom implementation.  Set the delegate to deal with 401 challenge concerns, if an authentication scheme in question deals an authentication interaction as part of it's request flow. (like adding a response header, or changing the 401 result to 302 of a login page or external sign-in location.)  
	Call context.Handled() at the end so that any default logic for this challenge will be skipped.

- #### OnHandleForbidden  
	A delegate assigned to this property will be invoked if Authorization fails and results in a Forbidden response.  
	Only use this if you know what you are doing and if you want to use custom implementation.  
	Set the delegate to handle Forbid.  
	Call context.Handled() at the end so that any default logic will be skipped.

<br/>
<br/>

## Additional Notes

### Basic Authentication Not Challenged
With ASP.NET Core, all the requests are not challenged for authentication by default. So don't worry if your *BasicUserValidationService* is not hit when you don't pass the required basic authentication details with the request. It is a normal behaviour. ASP.NET Core challenges authentication only when it is specifically told to do so either by decorating controller/method with *[Authorize]* filter attribute or by some other means. 

However, if you want all the requests to challenge authentication by default, depending on what you are using, you can add the below options line to *ConfigureServices* method on *Startup* class.

```C#
// On ASP.NET Core 6.0 onwards
services.AddAuthorization(options =>
{
	options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
});
```
  
If you are not using MVC but, using Endpoints on ASP.NET Core 3.0 or newer, you can add a chain method `.RequireAuthorization()` to the endpoint map under *Configure* method on *Startup* class as shown below.

```C#
// ASP.NET Core 6.0 onwards
app.UseEndpoints(endpoints =>
{
	endpoints.MapGet("/", async context =>
	{
		await context.Response.WriteAsync("Hello World!");
	}).RequireAuthorization();  // NOTE THIS HERE!!!! 
});
``` 

### Multiple Authentication Schemes
ASP.NET Core supports adding multiple authentication schemes which this library also supports. Just need to use the extension method which takes scheme name as parameter. The rest is all same. This can be achieved in many different ways. Below is just a quick rough example.   

Please note that scheme name parameter can be any string you want.

```C#
public void ConfigureServices(IServiceCollection services)
{
	services.AddTransient<IUserRepository, InMemoryUserRepository>();
		
	services.AddAuthentication("Scheme1")

		.AddBasic<BasicUserAuthenticationService>("Scheme1", options => { options.Realm = "My App"; })

		.AddBasic<BasicUserAuthenticationService_2>("Scheme2", options => { options.Realm = "My App"; })
		
		.AddBasic("Scheme3", options => 
		{ 
			options.Realm = "My App"; 
			options.Events = new BasicEvents
			{
				OnValidateCredentials = async (context) =>
				{
					var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();
					var user = await userRepository.GetUserByUsername(context.Username);
					var isValid = user != null && user.Password == context.Password;
					if (isValid)
					{
						context.Response.Headers.Add("ValidationCustomHeader", "From OnValidateCredentials");
						var claims = new[]
						{
							new Claim("CustomClaimType", "Custom Claim Value - from OnValidateCredentials")
						};
						context.ValidationSucceeded(claims);    // claims are optional
					}
					else
					{
						context.ValidationFailed();
					}
				}
			}
		});

	services.AddControllers();

	services.AddAuthorization(options =>
	{
		options.FallbackPolicy = new AuthorizationPolicyBuilder("Scheme1", "Scheme2", "Scheme3").RequireAuthenticatedUser().Build();
	});
}
```

<br/>
<br/>

## References
- [RFC 7617: Technical spec for HTTP Basic](https://tools.ietf.org/html/rfc7617)
- [ASP.NET Core Security documentation](https://docs.microsoft.com/en-us/aspnet/core/security)
- [aspnet/Security](https://github.com/dotnet/aspnetcore/tree/master/src/Security)
