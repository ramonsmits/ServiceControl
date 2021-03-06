﻿namespace NServiceBus.AcceptanceTesting
{
    using System;
    using System.Collections.Generic;
    using System.Reflection;
    using Support;

    public class EndpointConfigurationBuilder : IEndpointConfigurationFactory
    {
        public EndpointConfigurationBuilder()
        {
            configuration.EndpointMappings = new Dictionary<Type, Type>();
        }

        public EndpointConfigurationBuilder AuditTo(Address addressOfAuditQueue)
        {
            configuration.AddressOfAuditQueue = addressOfAuditQueue;
            return this;
        }

        public EndpointConfigurationBuilder ErrorTo(Address addressOfErrorQueue)
        {
            configuration.AddressOfErrorQueue = addressOfErrorQueue;
            return this;
        }

        public EndpointConfigurationBuilder AddMapping<T>(Type endpoint)
        {
            configuration.EndpointMappings.Add(typeof(T),endpoint);

            return this;
        }

        EndpointConfiguration CreateScenario()
        {
            configuration.BuilderType = GetType();

            return configuration;
        }

        public EndpointConfigurationBuilder EndpointSetup<T>() where T : IEndpointSetupTemplate, new()
        {
            return EndpointSetup<T>(c => { });
        }

        public EndpointConfigurationBuilder EndpointSetup<T>(Action<BusConfiguration> configurationBuilderCustomization = null) where T : IEndpointSetupTemplate, new()
        {
            if (configurationBuilderCustomization == null)
            {
                configurationBuilderCustomization = b => { };
            }
            configuration.GetConfiguration = (settings, routingTable) =>
                {
                    var endpointSetupTemplate = new T();
                    var scenarioConfigSource = new ScenarioConfigSource(configuration, routingTable);
                    return endpointSetupTemplate.GetConfiguration(settings, configuration, scenarioConfigSource, configurationBuilderCustomization);
                };

            return this;
        }

        EndpointConfiguration IEndpointConfigurationFactory.Get()
        {
            return CreateScenario();
        }


        readonly EndpointConfiguration configuration = new EndpointConfiguration();

        public EndpointConfigurationBuilder WithConfig<T>(Action<T> action) where T : new()
        {
            var config = new T();

            action(config);

            configuration.UserDefinedConfigSections[typeof (T)] = config;

            return this;
        }

        public EndpointConfigurationBuilder IncludeAssembly(Assembly assembly)
        {
            configuration.TypesToInclude.AddRange(assembly.GetTypes());

            return this;
        }
    }
}