namespace ServiceControl.Recoverability.API
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using NServiceBus;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServiceControl.Persistence.Recoverability;

    [ApiController]
    [Route("api")]
    public class FailureGroupsArchiveController(IMessageSession bus, IArchiveMessages archiver) : ControllerBase
    {
        [RequirePermission(Permissions.RecoverabilityGroupsArchive)]
        [Authorize(Policy = Permissions.RecoverabilityGroupsArchive)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/archive")]
        [HttpPost]
        public async Task<IActionResult> ArchiveGroupErrors(string groupId)
        {
            if (!archiver.IsOperationInProgressFor(groupId, ArchiveType.FailureGroup))
            {
                await archiver.StartArchiving(groupId, ArchiveType.FailureGroup);

                await bus.SendLocal<ArchiveAllInGroup>(m => { m.GroupId = groupId; });
            }

            return Accepted();
        }
    }
}