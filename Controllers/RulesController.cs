using System;
using System.Collections.Generic;
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
			if (model == null) return BadRequest(new { Success = false, Message = "Invalid model." });
			if (!Request.Headers.ContainsKey("Api-Secret")) return BadRequest(new { success = false, message = "Missing Secret header" });
			var values = Request.Headers["Api-Secret"];
			var apiSecret = Environment.GetEnvironmentVariable("AWSHELPER_API_SECRET");
			if (values.FirstOrDefault(x => x == apiSecret) == null) return Unauthorized(new { success = false, message = "Invalid secret header" });


			if (string.IsNullOrEmpty(model.Name) || string.IsNullOrWhiteSpace(model.Name)) return BadRequest(new { Success = false, Message = "Invalid name" });

			var namePrefix = Environment.GetEnvironmentVariable("AWSHELPER_NAME_PREFIX");
			var groupId = Environment.GetEnvironmentVariable("AWSHELPER_GROUP_ID");
			var accessId = Environment.GetEnvironmentVariable("AWSHELPER_ACCESS_ID");
			var accessSecret = Environment.GetEnvironmentVariable("AWSHELPER_ACCESS_SECRET");
			var endpoint = RegionEndpoint.GetBySystemName(Environment.GetEnvironmentVariable("AWSHELPER_REGION"));
			var client = new AmazonEC2Client(accessId, accessSecret, endpoint);

			var req = new DescribeSecurityGroupsRequest();
			req.GroupIds.Add(groupId);

			var request = new UpdateSecurityGroupRuleDescriptionsIngressRequest
			{
				GroupId = groupId
			};

			try
			{
				var secGroupRequest = new DescribeSecurityGroupsRequest();
				secGroupRequest.GroupIds.Add(groupId);

				var get = await client.DescribeSecurityGroupsAsync(secGroupRequest);

				var securityGroup = get.SecurityGroups.FirstOrDefault();
				if (securityGroup == null) return BadRequest(new { Success = false, Message = "Security group not found." });

				var description = $"{namePrefix}{model.Name}";

				var ipRangeListRemoved = new List<IpRange>();
				var ipRangeListAdded = new List<IpRange>();

				foreach (var permission in securityGroup.IpPermissions)
				{
					foreach (var ipRange in permission.Ipv4Ranges)
						if (description.Equals(ipRange.Description) && permission.ToPort == model.Port)
							ipRangeListRemoved.Add(ipRange);
					permission.Ipv4Ranges.RemoveAll(x => ipRangeListRemoved.Contains(x));
				}

				if (ipRangeListRemoved.Any())
				{
					var revokeRequest = new RevokeSecurityGroupIngressRequest();
					revokeRequest.GroupId = groupId;
					revokeRequest.IpPermissions.Add(new IpPermission
					{
						FromPort = model.Port,
						IpProtocol = model.Protocol,
						ToPort = model.Port,
						Ipv4Ranges = new List<IpRange>(ipRangeListRemoved)
					});
					await client.RevokeSecurityGroupIngressAsync(revokeRequest);
				}

				var authorizeRequest = new AuthorizeSecurityGroupIngressRequest();
				authorizeRequest.GroupId = groupId;
				var authorizeIpRange = new IpRange
				{
					CidrIp = $"{model.Ip}/32",
					Description = description
				};
				authorizeRequest.IpPermissions.Add(new IpPermission
				{
					FromPort = model.Port,
					IpProtocol = model.Protocol,
					ToPort = model.Port,
					Ipv4Ranges = new List<IpRange> { authorizeIpRange }
				});
				var authorizeResult = await client.AuthorizeSecurityGroupIngressAsync(authorizeRequest);

				return Ok(new
				{
					Success = true,
					Message = "Action completed."
				});
			}
			catch (Exception ex)
			{
				return BadRequest(new { Success = false, Message = ex.Message });
			}
		}
	}
}
