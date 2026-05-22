namespace ServiceControl.MessageFailures.Api
{
    using System.Threading.Tasks;
    using Infrastructure.WebApi;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Persistence;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi.Auth;

    [ApiController]
    [Route("api")]
    public class GetErrorByIdController(
        IErrorMessageDataStore store,
        IAuthorizationService authorizationService) : ControllerBase
    {
        [RequirePermission(Permissions.MessagesView)]
        [Authorize(Policy = Permissions.MessagesView)]
        [Route("errors/{failedMessageId:required:minlength(1)}")]
        [HttpGet]
        public async Task<ActionResult<FailedMessage>> ErrorBy(string failedMessageId)
        {
            var result = await store.ErrorBy(failedMessageId);

            if (result == null)
            {
                return NotFound();
            }

            // Resource-scope check: is this message's queue address in scope for this user?
            var scopeResult = await authorizationService.AuthorizeAsync(
                User,
                result,
                new PermissionRequirement(Permissions.MessagesView));

            if (!scopeResult.Succeeded)
            {
                var queueAddress = result.ProcessingAttempts.Count > 0
                    ? result.ProcessingAttempts[^1].FailureDetails?.AddressOfFailingEndpoint
                    : null;

                Response.ContentType = "application/json";
                Response.StatusCode = StatusCodes.Status403Forbidden;
                await Response.WriteAsJsonAsync(new
                {
                    error = "forbidden",
                    permission = Permissions.MessagesView,
                    resource = queueAddress,
                    reason = string.IsNullOrEmpty(queueAddress)
                        ? "Message has no resolvable queue address"
                        : $"Queue '{queueAddress}' is out of scope for permission '{Permissions.MessagesView}'"
                });
                return Empty;
            }

            return result;
        }

        [RequirePermission(Permissions.MessagesView)]
        [Authorize(Policy = Permissions.MessagesView)]
        [Route("errors/last/{failedMessageId:required:minlength(1)}")]
        [HttpGet]
        public async Task<ActionResult<FailedMessageView>> ErrorLastBy(string failedMessageId)
        {
            var result = await store.ErrorLastBy(failedMessageId);

            return result == null ? NotFound() : result;
        }
    }
}