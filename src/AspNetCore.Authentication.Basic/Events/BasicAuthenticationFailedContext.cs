﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Events
{
	using System;
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;

	/// <summary>
	///     Context used when authentication is failed.
	/// </summary>
	public class BasicAuthenticationFailedContext : ResultContext<BasicOptions>
	{
		/// <summary>
		///     Initializes a new instance of the <see cref="BasicAuthenticationFailedContext"/> type.
		/// </summary>
		/// <param name="context"></param>
		/// <param name="scheme"></param>
		/// <param name="options"></param>
		/// <param name="exception"></param>
		public BasicAuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, Exception exception)
			: base(context, scheme, options)
		{
			this.Exception = exception;
		}

		/// <summary>
		///     The Exception thrown when authenticating.
		/// </summary>
		public Exception Exception { get; }
	}
}
