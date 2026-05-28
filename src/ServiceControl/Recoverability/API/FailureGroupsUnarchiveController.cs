namespace ServiceControl.Recoverability.API
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using NServiceBus;
    using ServiceControl.Infrastructure.Auth.Rbac;
    using ServiceControl.Infrastructure.WebApi.Auth;
    using ServiceControl.Persistence.Recoverability;

    [ApiController]
    [Route("api")]
    public class FailureGroupsUnarchiveController(
        IMessageSession bus,
        IArchiveMessages archiver,
        IPermissionEvaluator permissionEvaluator) : ControllerBase
    {
        /// <summary>
        /// Unarchives all messages in the specified failure group.
        /// <para>
        /// <b>Fail-closed for scoped users:</b> failure groups span multiple queues and cannot be
        /// scope-checked against a single queue address. If the user holds only scope-restricted
        /// grants for <c>recoverabilitygroups:unarchive</c>, access is denied with 403.
        /// </para>
        /// </summary>
        [Authorize(Policy = Permissions.RecoverabilityGroupsUnarchive)]
        [Route("recoverability/groups/{groupId:required:minlength(1)}/errors/unarchive")]
        [HttpPost]
        public async Task<IActionResult> UnarchiveGroupErrors(string groupId)
        {
            // Fail-closed for scoped users: groups span queues and cannot be scope-checked.
            if (!permissionEvaluator.HasUnrestrictedGrant(User, Permissions.RecoverabilityGroupsUnarchive))
            {
                await AuthorizationHelpers.WriteScopeDenied403(
                    Response,
                    Permissions.RecoverabilityGroupsUnarchive,
                    queueAddress: groupId);
                return new EmptyResult();
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