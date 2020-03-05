using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace SampleApi.Controllers
{
    [Route("identity")]
    public class IdentityController : ControllerBase
    {
        private readonly ILogger<IdentityController> _logger;

        public IdentityController(ILogger<IdentityController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("private")]
        [Authorize("PrivatePolicy")]
        public ActionResult GetPrivateResource()
        {
            return new JsonResult("This is private resource");
        }

        [HttpGet]
        [Route("public")]
        [Authorize]
        public ActionResult GetPublicResource()
        {
            return new JsonResult("This is public resource");
        }
    }
}