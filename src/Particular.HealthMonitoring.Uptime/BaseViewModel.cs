namespace Particular.HealthMonitoring.Uptime
{
    using System;
    using ServiceControl.Infrastructure.DomainEvents;

    abstract class BaseViewModel
    {
        protected static bool TryHandle<T>(IDomainEvent @event, Action<T> applyFunc)
            where T : class, IDomainEvent
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