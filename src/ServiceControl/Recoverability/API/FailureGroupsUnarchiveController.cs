namespace ServiceControl.Recoverability.API
{
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using NServiceBus;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServiceControl.Persistence;
    using ServiceControl.Persistence.Recoverability;

    [ApiController]
    [Route("api")]
    public class FailureGroupsUnarchiveController(
        IMessageSession bus,
        IArchiveMessages archiver,
        IErrorMessageDataStore store,
        IAuthorizationService authorizationService) : ControllerBase
    {
        [Authorize(Policy = Permissions.RecoverabilityGroupsUnarchive)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/unarchive")]
        [HttpPost]
        public async Task<IActionResult> UnarchiveGroupErrors(string groupId)
        {
            // Resource-scope check: load the group and verify this user may operate on it.
            // Groups span multiple queues and cannot be verified against a single queue address.
            // Scoped users (scope-restricted grants only) are denied fail-closed — see
            // FailureGroupAuthorizationHandler for the rationale.
            var groupResult = await store.GetGroup(groupId, status: null, modified: null);
            var group = groupResult.Results.FirstOrDefault();
            if (group != null)
            {
                var scopeResult = await authorizationService.AuthorizeAsync(
                    User,
                    group,
                    new PermissionRequirement(Permissions.RecoverabilityGroupsUnarchive));

                if (!scopeResult.Succeeded)
                {
                    Response.ContentType = "application/json";
                    Response.StatusCode = StatusCodes.Status403Forbidden;
                    await Response.WriteAsJsonAsync(new
                    {
                        error = "forbidden",
                        permission = Permissions.RecoverabilityGroupsUnarchive,
                        resource = groupId,
                        reason = $"Group '{groupId}' cannot be scope-verified — access denied fail-closed for scoped users"
                    });
                    return Empty;
                }
            }

            if (!archiver.IsOperationInProgressFor(groupId, ArchiveType.FailureGroup))
            {
                await archiver.StartUnarchiving(groupId, ArchiveType.FailureGroup);

                await bus.SendLocal<UnarchiveAllInGroup>(m => { m.GroupId = groupId; });
            }

            return Accepted();
        }
    }
}