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
    public class FailureGroupsArchiveController(
        IMessageSession bus,
        IArchiveMessages archiver,
        IErrorMessageDataStore store,
        IAuthorizationService authorizationService) : ControllerBase
    {
        [RequirePermission(Permissions.RecoverabilityGroupsArchive)]
        [Authorize(Policy = Permissions.RecoverabilityGroupsArchive)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/archive")]
        [HttpPost]
        public async Task<IActionResult> ArchiveGroupErrors(string groupId)
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
                    new PermissionRequirement(Permissions.RecoverabilityGroupsArchive));

                if (!scopeResult.Succeeded)
                {
                    Response.ContentType = "application/json";
                    Response.StatusCode = StatusCodes.Status403Forbidden;
                    await Response.WriteAsJsonAsync(new
                    {
                        error = "forbidden",
                        permission = Permissions.RecoverabilityGroupsArchive,
                        resource = groupId,
                        reason = $"Group '{groupId}' cannot be scope-verified — access denied fail-closed for scoped users"
                    });
                    return Empty;
                }
            }

            if (!archiver.IsOperationInProgressFor(groupId, ArchiveType.FailureGroup))
            {
                await archiver.StartArchiving(groupId, ArchiveType.FailureGroup);

                await bus.SendLocal<ArchiveAllInGroup>(m => { m.GroupId = groupId; });
            }

            return Accepted();
        }
    }
}