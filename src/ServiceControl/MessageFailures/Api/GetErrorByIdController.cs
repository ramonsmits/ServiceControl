namespace ServiceControl.MessageFailures.Api
{
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Persistence;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi.Auth;

    [ApiController]
    [Route("api")]
    public class GetErrorByIdController(
        IErrorMessageDataStore store,
        IPermissionEvaluator permissionEvaluator,
        ICasbinResourceScopeChecker scopeChecker) : ControllerBase
    {
        [Authorize(Policy = Permissions.MessagesView)]
        [Route("errors/{failedMessageId:required:minlength(1)}")]
        [HttpGet]
        public async Task<IActionResult> ErrorBy(string failedMessageId)
        {
            var result = await store.ErrorBy(failedMessageId);

            if (result == null)
            {
                return NotFound();
            }

            // Resource-scope check: is this message's queue address in scope for this user?
            var queueAddress = result.ProcessingAttempts
                .LastOrDefault()
                ?.FailureDetails
                ?.AddressOfFailingEndpoint;

            var scopeResult = await scopeChecker.EnforceAsync(
                User,
                Permissions.MessagesView,
                queueAddress,
                HttpContext);

            if (scopeResult != null)
            {
                return scopeResult;
            }

            return Ok(result);
        }

        [Authorize(Policy = Permissions.MessagesView)]
        [Route("errors/last/{failedMessageId:required:minlength(1)}")]
        [HttpGet]
        public async Task<IActionResult> ErrorLastBy(string failedMessageId)
        {
            var result = await store.ErrorLastBy(failedMessageId);

            if (result == null)
            {
                return NotFound();
            }

            // Resource-scope check: consistent with ErrorBy — a scoped user must not view
            // a message whose queue is outside their scope.
            if (!permissionEvaluator.HasUnrestrictedGrant(User, Permissions.MessagesView)
                && !permissionEvaluator.IsInScope(User, Permissions.MessagesView, result.QueueAddress ?? string.Empty))
            {
                await AuthorizationHelpers.WriteScopeDenied403(Response, Permissions.MessagesView, result.QueueAddress);
                return Empty;
            }

            return Ok(result);
        }
    }
}