// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Tests
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Net;
	using System.Net.Http;
	using System.Net.Http.Headers;
	using System.Security.Claims;
	using System.Text.Json;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.Basic.Tests.Infrastructure;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Authorization;
	using Microsoft.AspNetCore.TestHost;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Options;
	using Xunit;

	public class BasicHandlerTests : IDisposable
	{
		public BasicHandlerTests()
		{
			this._server = TestServerBuilder.BuildTestServer();
			this._client = this._server.CreateClient();

			this._serverWithService = TestServerBuilder.BuildTestServerWithService();
			this._clientWithService = this._serverWithService.CreateClient();

			this._serverWithServiceFactory = TestServerBuilder.BuildTestServerWithServiceFactory();
			this._clientWithServiceFactory = this._serverWithService.CreateClient();
		}

		public void Dispose()
		{
			this._client?.Dispose();
			this._server?.Dispose();

			this._clientWithService?.Dispose();
			this._serverWithService?.Dispose();

			this._serverWithServiceFactory?.Dispose();
			this._clientWithServiceFactory?.Dispose();
		}

		private const string HeaderFromEventsKey = nameof(HeaderFromEventsKey);
		private const string HeaderFromEventsValue = nameof(HeaderFromEventsValue);

		private readonly TestServer _server;
		private readonly HttpClient _client;
		private readonly TestServer _serverWithService;
		private readonly HttpClient _clientWithService;
		private readonly TestServer _serverWithServiceFactory;
		private readonly HttpClient _clientWithServiceFactory;

		private async Task<ClaimsPrincipalDto> DeserializeClaimsPrincipalAsync(HttpResponseMessage response)
		{
			return JsonSerializer.Deserialize<ClaimsPrincipalDto>(await response.Content.ReadAsStringAsync());
		}

		private class FakeBasicUserAuthenticationServiceLocal1 : IBasicUserAuthenticationService
		{
			public Task<IBasicUser> AuthenticateAsync(string username, string password)
			{
				return Task.FromResult((IBasicUser)new FakeBasicUser(username));
			}
		}

		private class FakeBasicUserAuthenticationServiceLocal2 : IBasicUserAuthenticationService
		{
			public Task<IBasicUser> AuthenticateAsync(string username, string password)
			{
				return Task.FromResult((IBasicUser)new FakeBasicUser(username));
			}
		}

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)

		[Fact]
		public async Task HandleAuthenticate_IgnoreAuthenticationIfAllowAnonymous()
		{
			using HttpResponseMessage response = await this._clientWithService.GetAsync(TestServerBuilder.AnonymousUrl);
			ClaimsPrincipalDto principal = await this.DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.False(principal.Identity.IsAuthenticated);
		}

#endif

		[Fact]
		public async Task HandleAuthenticate_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_invalid_scheme_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_and_principal_null()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.RejectPrincipal();

					Assert.Null(context.Result);
					Assert.Null(context.Principal);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_not_null()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					context.Fail("test");

					Assert.NotNull(context.Result);
					Assert.NotNull(context.Principal);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnAuthenticationSucceeded_result_null()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnAuthenticationSucceeded = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_not_null()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					context.ValidationSucceeded(new List<Claim> { FakeUsers.FakeRoleClaim, new Claim(ClaimTypes.Name, "my_test") });

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);
			ClaimsPrincipalDto principal = await this.DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(principal.Claims, c => c.Type == FakeUsers.FakeRoleClaim.Type && c.Value == FakeUsers.FakeRoleClaim.Value);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);
			ClaimsPrincipalDto principal = await this.DeserializeClaimsPrincipalAsync(response);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			Assert.Contains(principal.Claims, c => c.Type == FakeUsers.FakeNameClaim.Type && c.Value == FakeUsers.FakeNameClaim.Value); // coming from provider, so provider called
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null_without_provider_and_OnAuthenticationFailed_does_not_throw()
		{
			string expectedExceptionMessage = $"Either {nameof(MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicEvents.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.";

			using TestServer server = TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};

				options.Events.OnAuthenticationFailed = context =>
				{
					Assert.Null(context.Result);
					Assert.NotNull(context.Exception);
					Assert.IsType<InvalidOperationException>(context.Exception);
					Assert.Equal(expectedExceptionMessage, context.Exception.Message);

					context.NoResult();

					Assert.NotNull(context.Result);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_OnValidateCredentials_result_null_without_provider_and_OnAuthenticationFailed_throws()
		{
			string expectedExceptionMessage = $"Either {nameof(MadEyeMatt.AspNetCore.Authentication.Basic.Events.BasicEvents.OnValidateCredentials)} delegate on configure options {nameof(BasicOptions.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.";

			using TestServer server = TestServerBuilder.BuildTestServer(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnValidateCredentials = context =>
				{
					Assert.Null(context.Result);

					return Task.CompletedTask;
				};

				options.Events.OnAuthenticationFailed = context =>
				{
					Assert.NotNull(context.Exception);
					Assert.IsType<InvalidOperationException>(context.Exception);
					Assert.Equal(expectedExceptionMessage, context.Exception.Message);

					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();

			InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
			{
				using HttpResponseMessage response = await client.SendAsync(request);

				Assert.False(response.IsSuccessStatusCode);
				Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			});

			Assert.Equal(expectedExceptionMessage, exception.Message);
		}

		[Fact]
		public async Task HandleAuthenticate_Password_empty()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUserWithEmptyPassword.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await this._clientWithService.SendAsync(request);

			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using HttpResponseMessage response = await this._clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_invalid_scheme_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using HttpResponseMessage response = await this._clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await this._clientWithService.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await this._clientWithService.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_invalid_key_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue(BasicDefaults.AuthenticationScheme, "<invalid>");
			using HttpResponseMessage response = await this._clientWithServiceFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_invalid_scheme_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = new AuthenticationHeaderValue("INVALID", "test");
			using HttpResponseMessage response = await this._clientWithServiceFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_success()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await this._clientWithServiceFactory.SendAsync(request);
			Assert.True(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_TBasicUserValidationService_Via_Factory_Unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await this._clientWithServiceFactory.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleAuthenticate_unauthorized()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.BaseUrl);
			using HttpResponseMessage response = await this._client.SendAsync(request);
			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
		}

		[Fact]
		public async Task HandleChallenge()
		{
			using HttpResponseMessage response = await this._clientWithService.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallenge_using_OnHandleChallenge()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.NotEmpty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleChallenge_using_OnHandleChallenge_and_SuppressWWWAuthenticateHeader()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.SuppressWWWAuthenticateHeader = true;
				options.Events.OnHandleChallenge = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleChallenge_using_SuppressWWWAuthenticateHeader()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.SuppressWWWAuthenticateHeader = true;
			});
			using HttpClient client = server.CreateClient();
			using HttpResponseMessage response = await client.GetAsync(TestServerBuilder.BaseUrl);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
			Assert.Empty(response.Headers.WwwAuthenticate);
		}

		[Fact]
		public async Task HandleChallenge_verify_challenge_www_authenticate_header()
		{
			using HttpResponseMessage response = await this._client.GetAsync(TestServerBuilder.BaseUrl);
			Assert.False(response.IsSuccessStatusCode);

			HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticateHeader = response.Headers.WwwAuthenticate;
			Assert.NotEmpty(wwwAuthenticateHeader);

			AuthenticationHeaderValue wwwAuthenticateHeaderToMatch = Assert.Single(wwwAuthenticateHeader);
			Assert.NotNull(wwwAuthenticateHeaderToMatch);
			Assert.Equal(BasicDefaults.AuthenticationScheme, wwwAuthenticateHeaderToMatch.Scheme);
			Assert.Equal($"realm=\"{TestServerBuilder.Realm}\", charset=\"UTF-8\"", wwwAuthenticateHeaderToMatch.Parameter);
		}

		[Fact]
		public async Task HandleForbidden()
		{
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ForbiddenUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await this._clientWithService.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.False(response.Headers.Contains(HeaderFromEventsKey));
		}

		[Fact]
		public async Task HandleForbidden_using_OnHandleForbidden()
		{
			using TestServer server = TestServerBuilder.BuildTestServerWithService(options =>
			{
				options.Realm = TestServerBuilder.Realm;
				options.Events.OnHandleForbidden = context =>
				{
					context.HttpContext.Response.Headers.Add(HeaderFromEventsKey, HeaderFromEventsValue);
					return Task.CompletedTask;
				};
			});
			using HttpClient client = server.CreateClient();
			using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ForbiddenUrl);
			request.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response = await client.SendAsync(request);

			Assert.False(response.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
			Assert.True(response.Headers.Contains(HeaderFromEventsKey));
			Assert.Contains(HeaderFromEventsValue, response.Headers.GetValues(HeaderFromEventsKey));
		}

		[Fact]
		public async Task MultiScheme()
		{
			ClaimDto claimRole = new ClaimDto(FakeUsers.FakeRoleClaim);
			List<string> schemes = new List<string> { "Scheme1", "Scheme2" };

			using TestServer server = TestServerBuilder.BuildTestServer(services =>
			{
				services.AddAuthentication("Scheme1")
					.AddBasic("Scheme1", options =>
					{
						options.Realm = TestServerBuilder.Realm;
						options.Events.OnValidateCredentials = context =>
						{
							User user = FakeUsers.Users.FirstOrDefault(u => u.Username.Equals(context.Username, StringComparison.OrdinalIgnoreCase) && u.Password.Equals(context.Password, StringComparison.OrdinalIgnoreCase));
							if(user != null)
							{
								context.Response.Headers.Add("X-Custom", "Scheme1");
								context.ValidationSucceeded(new List<Claim> { FakeUsers.FakeRoleClaim });
							}
							else
							{
								context.ValidationFailed();
							}

							return Task.CompletedTask;
						};
					})
					.AddBasic<FakeBasicUserAuthenticationServiceLocal1>("Scheme2", options =>
					{
						options.Realm = TestServerBuilder.Realm;
					});

#if !(NET461 || NETSTANDARD2_0 || NETCOREAPP2_1)
				services.Configure<AuthorizationOptions>(options => options.FallbackPolicy = new AuthorizationPolicyBuilder(schemes.ToArray()).RequireAuthenticatedUser().Build());
#endif
			});

			using HttpClient client = server.CreateClient();

			using HttpRequestMessage request1 = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[0]);
			request1.Headers.Authorization = FakeUsers.FakeUser.ToAuthenticationHeaderValue();
			using HttpResponseMessage response1 = await client.SendAsync(request1);
			Assert.True(response1.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response1.StatusCode);
			ClaimsPrincipalDto response1Principal = await this.DeserializeClaimsPrincipalAsync(response1);
			Assert.Contains(response1.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "Scheme1"));
			Assert.Contains(response1Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);


			using HttpRequestMessage request2 = new HttpRequestMessage(HttpMethod.Get, TestServerBuilder.ClaimsPrincipalUrl + "?scheme=" + schemes[1]);
			request2.Headers.Authorization = new User("test", "test").ToAuthenticationHeaderValue();
			using HttpResponseMessage response2 = await client.SendAsync(request2);
			Assert.True(response2.IsSuccessStatusCode);
			Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
			ClaimsPrincipalDto response2Principal = await this.DeserializeClaimsPrincipalAsync(response2);
			Assert.DoesNotContain(response2.Headers, r => r.Key == "X-Custom" && r.Value.Any(v => v == "Scheme1"));
			Assert.DoesNotContain(response2Principal.Claims, c => c.Type == claimRole.Type && c.Value == claimRole.Value);
		}

		[Fact]
		public async Task TBasicUserValidationService_Verify_Handler()
		{
			IServiceProvider services = this._serverWithService.Host.Services;
			IAuthenticationSchemeProvider schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			AuthenticationScheme scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(BasicHandler), scheme.HandlerType);

			IOptionsSnapshot<BasicOptions> optionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			BasicOptions options = optionsSnapshot.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.Null(options.Events?.OnValidateCredentials);
			Assert.NotNull(options.BasicUserValidationServiceType);
			Assert.Equal(typeof(FakeBasicUserAuthenticationService), options.BasicUserValidationServiceType);

			IBasicUserAuthenticationService apiKeyProvider = services.GetService<IBasicUserAuthenticationService>();
			Assert.NotNull(apiKeyProvider);
			Assert.Equal(typeof(FakeBasicUserAuthenticationService), apiKeyProvider.GetType());
		}

		[Fact]
		public async Task TBasicUserValidationService_Via_Factory_Verify_Handler()
		{
			IServiceProvider services = this._serverWithServiceFactory.Host.Services;
			IAuthenticationSchemeProvider schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			AuthenticationScheme scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(BasicHandler), scheme.HandlerType);

			IOptionsSnapshot<BasicOptions> optionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			BasicOptions options = optionsSnapshot.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.Null(options.Events?.OnValidateCredentials);
			Assert.Null(options.BasicUserValidationServiceType);

			IBasicUserAuthenticationServiceFactory basicUserValidationServiceFactory = services.GetService<IBasicUserAuthenticationServiceFactory>();
			Assert.NotNull(basicUserValidationServiceFactory);
		}

		[Fact]
		public async Task Verify_Handler()
		{
			IServiceProvider services = this._server.Host.Services;
			IAuthenticationSchemeProvider schemeProvider = services.GetRequiredService<IAuthenticationSchemeProvider>();
			Assert.NotNull(schemeProvider);

			AuthenticationScheme scheme = await schemeProvider.GetDefaultAuthenticateSchemeAsync();
			Assert.NotNull(scheme);
			Assert.Equal(typeof(BasicHandler), scheme.HandlerType);

			IOptionsSnapshot<BasicOptions> optionsSnapshot = services.GetService<IOptionsSnapshot<BasicOptions>>();
			BasicOptions options = optionsSnapshot.Get(scheme.Name);
			Assert.NotNull(options);
			Assert.NotNull(options.Events?.OnValidateCredentials);
			Assert.Null(options.BasicUserValidationServiceType);

			IBasicUserAuthenticationService apiKeyProvider = services.GetService<IBasicUserAuthenticationService>();
			Assert.Null(apiKeyProvider);
		}
	}
}
