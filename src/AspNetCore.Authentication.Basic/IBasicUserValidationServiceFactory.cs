﻿// Copyright (c) Matthias Gernand. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

namespace AspNetCore.Authentication.Basic
{
	/// <summary>
	/// Implementation of this interface will be used by the 'Basic' authentication handler to get a schema specific <see cref="IBasicUserValidationService"/>.
	/// </summary>
	public interface IBasicUserValidationServiceFactory
	{
		/// <summary>
		/// Implementation of the service creation logic.
		/// </summary>
		/// <param name="authenticationSchemaName"></param>
		/// <returns></returns>
		IBasicUserValidationService CreateBasicUserValidationService(string authenticationSchemaName);
	}
}