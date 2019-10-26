using System;
using System.Linq;
using System.Threading.Tasks;
using Amazon;
using Amazon.EC2;
using Amazon.EC2.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AWSHelper.SecurityGroup.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class RulesController : ControllerBase
	{

		private readonly ILogger<RulesController> _logger;

		public RulesController(ILogger<RulesController> logger)
		{
			_logger = logger;
		}

		[HttpPost]
		public async Task<IActionResult> Post(IpModel model)
		{
			if (!Request.Headers.ContainsKey("Api-Secret")) return BadRequest(new { success = false, message = "Missing Secret header" });
			var values = Request.Headers["Api-Secret"];
			var apiSecret = Environment.GetEnvironmentVariable("AWS_API_SECRET");
			if (values.FirstOrDefault(x => x == apiSecret) == null) return Unauthorized(new { success = false, message = "Invalid secret header" });

			var namePrefix = Environment.GetEnvironmentVariable("AWS_NAME_PREFIX");
			var groupId = Environment.GetEnvironmentVariable("AWS_GROUP_ID");
			var accessId = Environment.GetEnvironmentVariable("AWS_ACCESS_ID");
			var accessSecret = Environment.GetEnvironmentVariable("AWS_ACCESS_SECRET");
			var endpoint = RegionEndpoint.GetBySystemName(Environment.GetEnvironmentVariable("AWS_REGION"));
			var client = new AmazonEC2Client(accessId, accessSecret, endpoint);

			var req = new DescribeSecurityGroupsRequest();
			req.GroupIds.Add(groupId);

			var request = new UpdateSecurityGroupRuleDescriptionsIngressRequest
			{
				GroupId = groupId
			};

			var ipPermission = new IpPermission
			{
				FromPort = model.Port,
				ToPort = model.Port,
				IpProtocol = model.Protocol
			};

			ipPermission.Ipv4Ranges.Add(new IpRange { CidrIp = $"{model.Ip}/32", Description = $"{namePrefix}{model.Name}" });
			request.IpPermissions.Add(ipPermission);

			var result = await client.UpdateSecurityGroupRuleDescriptionsIngressAsync(request);

			return Ok(new
			{
				Success = result.HttpStatusCode == System.Net.HttpStatusCode.OK,
				Message = "Action completed."
			});
		}
	}
}
