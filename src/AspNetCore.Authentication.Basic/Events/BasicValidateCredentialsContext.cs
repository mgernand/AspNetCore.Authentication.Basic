﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Events
{
	using System;
	using System.Collections.Generic;
	using System.Security.Claims;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;

	/// <summary>
	///     Context used for validating credentials.
	/// </summary>
	public class BasicValidateCredentialsContext : ResultContext<BasicOptions>
	{
		/// <summary>
		///      Initializes a new instance of the <see cref="BasicValidateCredentialsContext"/> type.
		/// </summary>
		/// <param name="context"></param>
		/// <param name="scheme"></param>
		/// <param name="options"></param>
		/// <param name="username"></param>
		/// <param name="password"></param>
		public BasicValidateCredentialsContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, string username, string password)
			: base(context, scheme, options)
		{
			this.Username = username;
			this.Password = password;
		}

		/// <summary>
		///     Gets the Username.
		/// </summary>
		public string Username { get; }

		/// <summary>
		///     Gets the Password.
		/// </summary>
		public string Password { get; }

		/// <summary>
		///     Calling this method will handle construction of authentication principal (<see cref="ClaimsPrincipal" />) from the
		///     user details
		///     which will be assigned to the <see cref="ResultContext{TOptions}.Principal" /> property
		///     and <see cref="ResultContext{TOptions}.Success" /> method will also be called.
		/// </summary>
		/// <param name="claims">Claims to be added to the identity.</param>
		public void ValidationSucceeded(IEnumerable<Claim> claims = null)
		{
			this.Principal = BasicUtils.BuildClaimsPrincipal(this.Username, this.Scheme.Name, this.Options.ClaimsIssuer, claims);
			this.Success();
		}

		/// <summary>
		///     If parameter <paramref name="failureMessage" /> passed is empty or null then NoResult() method is called
		///     otherwise, <see cref="ResultContext{TOptions}.Fail(string)" /> method will be called.
		/// </summary>
		/// <param name="failureMessage">(Optional) The failure message.</param>
		public void ValidationFailed(string failureMessage = null)
		{
			if(string.IsNullOrWhiteSpace(failureMessage))
			{
				this.NoResult();
				return;
			}

			this.Fail(failureMessage);
		}

		/// <summary>
		///     Calling this method is same as calling <see cref="ResultContext{TOptions}.Fail(Exception)" /> method.
		/// </summary>
		/// <param name="failureException">The failure exception.</param>
		public void ValidationFailed(Exception failureException)
		{
			this.Fail(failureException);
		}
	}
}
