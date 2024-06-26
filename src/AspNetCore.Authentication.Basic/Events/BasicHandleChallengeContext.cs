﻿// Copyright (c) Mihir Dilip. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace MadEyeMatt.AspNetCore.Authentication.Basic.Events
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;

	/// <summary>
	///     Context used when challenging unauthorized response.
	/// </summary>
	public class BasicHandleChallengeContext : PropertiesContext<BasicOptions>
	{
		/// <summary>
		///     Constructor.
		/// </summary>
		/// <param name="context"></param>
		/// <param name="scheme"></param>
		/// <param name="options"></param>
		/// <param name="properties"></param>
		public BasicHandleChallengeContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, AuthenticationProperties properties)
			: base(context, scheme, options, properties)
		{
		}

		/// <summary>
		///     Gets IsHandled property.
		///     True means response is handled and any default logic for this challenge will be skipped.
		/// </summary>
		public bool IsHandled { get; private set; }

		/// <summary>
		///     Marks as response handled and any default logic for this challenge will be skipped.
		/// </summary>
		public void Handled()
		{
			this.IsHandled = true;
		}
	}
}
