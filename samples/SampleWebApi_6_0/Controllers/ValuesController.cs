﻿using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace SampleWebApi_6_0.Controllers
{
	using Microsoft.AspNetCore.Authorization;

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
			var sb = new StringBuilder();
			foreach (var claim in User.Claims)
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