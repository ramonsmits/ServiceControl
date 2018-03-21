namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using Particular.HealthMonitoring.Uptime.Api;
    using ServiceControl.Infrastructure.DomainEvents;

    static class EventHelper
    {
        public static bool TryApply<T>(this IHeartbeatEvent @event, Func<T, IDomainEvent> applyFunc)
            where T : class, IHeartbeatEvent
        {
            var typed = @event as T;
            if (typed != null)
            {
                applyFunc(typed);
                return true;
            }
            return false;
        }
    }
}