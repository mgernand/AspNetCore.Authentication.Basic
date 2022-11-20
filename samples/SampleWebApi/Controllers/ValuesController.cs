﻿namespace SampleWebApi.Controllers
{
	using System.Collections.Generic;
	using System.Security.Claims;
	using System.Text;
	using Microsoft.AspNetCore.Authorization;
	using Microsoft.AspNetCore.Mvc;

	[Route("api/[controller]")]
	[ApiController]
	public class ValuesController : ControllerBase
	{
		// GET api/values
		[HttpGet]
		public ActionResult<IEnumerable<string>> Get()
		{
			return new string[] { "value1", "value2" };
		}

		// GET api/values/ones
		[HttpGet("ones")]
		[Authorize(AuthenticationSchemes = "Test2")]
		public ActionResult<IEnumerable<string>> Get_Test2()
		{
			return new string[] { "value1" };
		}

		// GET api/values/twos
		[HttpGet("twos")]
		[Authorize(AuthenticationSchemes = "Test3")]
		public ActionResult<IEnumerable<string>> Get_Test3()
		{
			return new string[] { "value2" };
		}

		[HttpGet("claims")]
		public ActionResult<string> Claims()
		{
			StringBuilder sb = new StringBuilder();
			foreach(Claim claim in this.User.Claims)
			{
				sb.AppendLine($"{claim.Type}: {claim.Value}");
			}

			return sb.ToString();
		}

		[HttpGet("forbid")]
		public new IActionResult Forbid()
		{
			return base.Forbid();
		}
	}
}
