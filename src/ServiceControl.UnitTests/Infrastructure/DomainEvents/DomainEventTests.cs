namespace ServiceControl.UnitTests.Infrastructure.DomainEvents
{
    using System.Linq;
    using Autofac;
    using NUnit.Framework;
    using ServiceControl.Infrastructure.DomainEvents;

    [TestFixture]
    public class DomainEventTests
    {
        [Test]
        public void InvokesDomainEventHandlers()
        {
            var builder = new ContainerBuilder();
            var eventHandler1 = new DummyDomainEventHandler();
            var eventHandler2 = new DummyDomainEventHandler();
            var eventHandler3 = new GeneralDomainEventHandler();
            builder.RegisterInstance(eventHandler1).AsImplementedInterfaces();
            builder.RegisterInstance(eventHandler2).AsImplementedInterfaces();
            builder.RegisterInstance(eventHandler3).AsImplementedInterfaces();
            var container = builder.Build();

            var domainEvents = new DomainEvents();
            domainEvents.SetContainer(container);

            domainEvents.Raise(new DummyDomainEvent());

            Assert.AreEqual(1, eventHandler1.WasCalled);
            Assert.AreEqual(1, eventHandler2.WasCalled);
            Assert.AreEqual(1, eventHandler3.WasCalled);
        }

        [Test]
        public void AllDomainEventHandlersArePublic()
        {
            var allTypes = typeof(DomainEvents).Assembly.GetTypes();
            var handlerTypes = allTypes.Where(t => t.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IDomainHandler<>))).ToArray();

            foreach (var handlerType in handlerTypes)
            {
                Assert.True(handlerType.IsPublic, $"Expected {handlerType} to be public.");
            }
        }

        public class DummyDomainEvent : IDomainEvent
        {
        }

        public class DummyDomainEventHandler : IDomainHandler<DummyDomainEvent>
        {
            public int WasCalled { get; private set; }
            public void Handle(DummyDomainEvent domainEvent)
            {
                WasCalled++;
            }
        }

        public class GeneralDomainEventHandler : IDomainHandler<IDomainEvent>
        {
            public int WasCalled { get; private set; }
            public void Handle(IDomainEvent domainEvent)
            {
                WasCalled++;
            }
        }
    }
}