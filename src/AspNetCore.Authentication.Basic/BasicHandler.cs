﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic
{
	using System;
	using System.Net.Http.Headers;
	using System.Runtime.CompilerServices;
	using System.Security.Claims;
	using System.Text;
	using System.Text.Encodings.Web;
	using System.Threading.Tasks;
	using MadEyeMatt.AspNetCore.Authentication.Basic.Events;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Authorization;
	using Microsoft.AspNetCore.Http;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Options;
	using Microsoft.Net.Http.Headers;

	/// <summary>
	///     Inherited from <see cref="AuthenticationHandler{TOptions}" /> for basic authentication.
	/// </summary>
	public class BasicHandler : AuthenticationHandler<BasicOptions>
	{
		/// <summary>
		///     Basic Handler Constructor.
		/// </summary>
		/// <param name="options"></param>
		/// <param name="logger"></param>
		/// <param name="encoder"></param>
		public BasicHandler(IOptionsMonitor<BasicOptions> options, ILoggerFactory logger, UrlEncoder encoder)
			: base(options, logger, encoder)
		{
		}

		private string Challenge => $"{BasicDefaults.AuthenticationScheme} realm=\"{this.Options.Realm}\", charset=\"UTF-8\"";

		/// <summary>
		///     Get or set <see cref="BasicEvents" />.
		/// </summary>
		protected new BasicEvents Events
		{
			get => (BasicEvents)base.Events;
			set => base.Events = value;
		}

		/// <summary>
		///     Create an instance of <see cref="BasicEvents" />.
		/// </summary>
		/// <returns></returns>
		protected override Task<object> CreateEventsAsync()
		{
			return Task.FromResult<object>(new BasicEvents());
		}

		/// <summary>
		///     Searches the 'Authorization' header for 'Basic' scheme with base64 encoded username:password string value of which
		///     is validated using implementation of <see cref="IBasicUserAuthenticationService" /> passed as type parameter when
		///     setting up basic authentication in the Startup.cs
		/// </summary>
		/// <returns>
		///     <see cref="AuthenticateResult" />
		/// </returns>
		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			if(this.IgnoreAuthenticationIfAllowAnonymous())
			{
				this.Logger.LogDebug("AllowAnonymous found on the endpoint so request was not authenticated.");
				return AuthenticateResult.NoResult();
			}

			if(!this.Request.Headers.ContainsKey(HeaderNames.Authorization))
			{
				this.Logger.LogInformation("No 'Authorization' header found in the request.");
				return AuthenticateResult.NoResult();
			}

			if(!AuthenticationHeaderValue.TryParse(this.Request.Headers[HeaderNames.Authorization], out AuthenticationHeaderValue headerValue))
			{
				this.Logger.LogInformation("No valid 'Authorization' header found in the request.");
				return AuthenticateResult.NoResult();
			}

			if(!headerValue.Scheme.Equals(BasicDefaults.AuthenticationScheme, StringComparison.OrdinalIgnoreCase))
			{
				this.Logger.LogInformation($"'Authorization' header found but the scheme is not a '{BasicDefaults.AuthenticationScheme}' scheme.");
				return AuthenticateResult.NoResult();
			}

			BasicCredentials credentials;
			try
			{
				credentials = this.DecodeBasicCredentials(headerValue.Parameter);
			}
			catch(Exception exception)
			{
				this.Logger.LogError(exception, "Error decoding credentials from header value.");
				return AuthenticateResult.Fail("Error decoding credentials from header value." + Environment.NewLine + exception.Message);
			}

			try
			{
				AuthenticateResult validateCredentialsResult = await this.RaiseAndHandleEventValidateCredentialsAsync(credentials).ConfigureAwait(false);
				if(validateCredentialsResult != null)
				{
					// If result is set then return it.
					return validateCredentialsResult;
				}

				// Validate using the implementation of IBasicUserValidationService.
				IBasicUser validatedBasicUser = await this.ValidateUsingBasicUserValidationServiceAsync(credentials.Username, credentials.Password).ConfigureAwait(false);
				if(validatedBasicUser == null)
				{
					this.Logger.LogError($"Invalid user provided by {nameof(IBasicUserAuthenticationService)}.");
					return AuthenticateResult.Fail("Invalid username or password.");
				}

				return await this.RaiseAndHandleAuthenticationSucceededAsync(validatedBasicUser).ConfigureAwait(false);
			}
			catch(Exception exception)
			{
				BasicAuthenticationFailedContext authenticationFailedContext = new BasicAuthenticationFailedContext(this.Context, this.Scheme, this.Options, exception);
				await this.Events.AuthenticationFailedAsync(authenticationFailedContext).ConfigureAwait(false);

				if(authenticationFailedContext.Result != null)
				{
					return authenticationFailedContext.Result;
				}

				throw;
			}
		}

		/// <inheritdoc />
		protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
		{
			// Raise handle forbidden event.
			BasicHandleForbiddenContext handleForbiddenContext = new BasicHandleForbiddenContext(this.Context, this.Scheme, this.Options, properties);
			await this.Events.HandleForbiddenAsync(handleForbiddenContext).ConfigureAwait(false);
			if(handleForbiddenContext.IsHandled)
			{
				return;
			}

			await base.HandleForbiddenAsync(properties);
		}

		/// <summary>
		///     Handles the un-authenticated requests.
		///     Returns 401 status code in response.
		///     If <see cref="BasicOptions.SuppressWWWAuthenticateHeader" /> is not set then,
		///     adds 'WWW-Authenticate' response header with 'Basic' authentication scheme and 'Realm'
		///     to let the client know that 'Basic' authentication scheme is being used by the system.
		/// </summary>
		/// <param name="properties">
		///     <see cref="AuthenticationProperties" />
		/// </param>
		/// <returns>A Task.</returns>
		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			// Raise handle challenge event.
			BasicHandleChallengeContext handleChallengeContext = new BasicHandleChallengeContext(this.Context, this.Scheme, this.Options, properties);
			await this.Events.HandleChallengeAsync(handleChallengeContext).ConfigureAwait(false);
			if(handleChallengeContext.IsHandled)
			{
				return;
			}

			if(!this.Options.SuppressWWWAuthenticateHeader)
			{
				this.Response.Headers[HeaderNames.WWWAuthenticate] = this.Challenge;
			}

			await base.HandleChallengeAsync(properties);
		}

		private async Task<AuthenticateResult> RaiseAndHandleEventValidateCredentialsAsync(BasicCredentials credentials)
		{
			BasicValidateCredentialsContext validateCredentialsContext = new BasicValidateCredentialsContext(this.Context, this.Scheme, this.Options, credentials.Username, credentials.Password);
			await this.Events.ValidateCredentialsAsync(validateCredentialsContext).ConfigureAwait(false);

			if(validateCredentialsContext.Result != null)
			{
				return validateCredentialsContext.Result;
			}

			if(validateCredentialsContext.Principal?.Identity != null && validateCredentialsContext.Principal.Identity.IsAuthenticated)
			{
				// If claims principal is set and is authenticated then build a ticket by calling and return success.
				validateCredentialsContext.Success();
				return validateCredentialsContext.Result;
			}

			return null;
		}

		private async Task<AuthenticateResult> RaiseAndHandleAuthenticationSucceededAsync(IBasicUser basicUser)
		{
			// ..create claims principal.
			ClaimsPrincipal principal = BasicUtils.BuildClaimsPrincipal(basicUser.UserName, this.Scheme.Name, this.ClaimsIssuer, basicUser.Claims);

			// Raise authentication succeeded event.
			BasicAuthenticationSucceededContext authenticationSucceededContext = new BasicAuthenticationSucceededContext(this.Context, this.Scheme, this.Options, principal);
			await this.Events.AuthenticationSucceededAsync(authenticationSucceededContext).ConfigureAwait(false);

			if(authenticationSucceededContext.Result != null)
			{
				return authenticationSucceededContext.Result;
			}

			if(authenticationSucceededContext.Principal?.Identity != null && authenticationSucceededContext.Principal.Identity.IsAuthenticated)
			{
				// If claims principal is set and is authenticated then build a ticket by calling and return success.
				authenticationSucceededContext.Success();
				return authenticationSucceededContext.Result;
			}

			this.Logger.LogError("No authenticated principal set.");
			return AuthenticateResult.Fail("No authenticated principal set.");
		}

		private bool IgnoreAuthenticationIfAllowAnonymous()
		{
			return this.Options.IgnoreAuthenticationIfAllowAnonymous
				&& this.Context.GetEndpoint()?.Metadata?.GetMetadata<IAllowAnonymous>() != null;
		}

		private async Task<IBasicUser> ValidateUsingBasicUserValidationServiceAsync(string username, string password)
		{
			IBasicUserAuthenticationService basicUserAuthenticationService = null;

			// Try to get an instance of the IBasicUserValidationServiceFactory.
			IBasicUserAuthenticationServiceFactory basicUserValidationServiceFactory = this.Context.RequestServices.GetService<IBasicUserAuthenticationServiceFactory>();

			// Try to get a IBasicUserValidationService instance from the factory.
			basicUserAuthenticationService = basicUserValidationServiceFactory?.CreateBasicUserAuthenticationService(this.Options.AuthenticationSchemeName);

			if(basicUserAuthenticationService == null && this.Options.BasicUserValidationServiceType != null)
			{
				basicUserAuthenticationService = ActivatorUtilities.GetServiceOrCreateInstance(this.Context.RequestServices, this.Options.BasicUserValidationServiceType) as IBasicUserAuthenticationService;
			}

			if(basicUserAuthenticationService == null)
			{
				throw new InvalidOperationException($"Either {nameof(this.Options.Events.OnValidateCredentials)} delegate on configure options {nameof(this.Options.Events)} should be set or use an extension method with type parameter of type {nameof(IBasicUserAuthenticationService)} or register an implementation of type {nameof(IBasicUserAuthenticationServiceFactory)} in the service collection.");
			}

			try
			{
				return await basicUserAuthenticationService.AuthenticateAsync(username, password).ConfigureAwait(false);
			}
			finally
			{
				if(basicUserAuthenticationService is IDisposable disposableBasicUserValidationService)
				{
					disposableBasicUserValidationService.Dispose();
				}
			}
		}

		private BasicCredentials DecodeBasicCredentials(string credentials)
		{
			string username;
			string password;
			try
			{
				// Convert the base64 encoded 'username:password' to normal string and parse username and password from colon(:) separated string.
				string usernameAndPassword = Encoding.UTF8.GetString(Convert.FromBase64String(credentials));
				string[] usernameAndPasswordSplit = usernameAndPassword.Split(':');
				if(usernameAndPasswordSplit.Length != 2)
				{
					throw new Exception("Invalid Basic authentication header.");
				}

				username = usernameAndPasswordSplit[0];
				password = usernameAndPasswordSplit[1];
			}
			catch(Exception e)
			{
				throw new Exception($"Problem decoding '{BasicDefaults.AuthenticationScheme}' scheme credentials.", e);
			}

			if(string.IsNullOrWhiteSpace(username))
			{
				throw new Exception("Username cannot be empty.");
			}

			return new BasicCredentials(username, password);
		}

		private struct BasicCredentials
		{
			public BasicCredentials(string username, string password)
			{
				this.Username = username;
				this.Password = password ?? string.Empty;
			}

			public string Username { get; }
			public string Password { get; }
		}
	}
}
