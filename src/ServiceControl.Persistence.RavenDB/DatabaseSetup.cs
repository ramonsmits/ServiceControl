namespace ServiceControl.Persistence.RavenDB
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using System.Threading;
    using System.Threading.Tasks;
    using Raven.Client.Documents;
    using Raven.Client.Documents.Indexes;
    using Raven.Client.Documents.Operations.Expiration;
    using Raven.Client.Exceptions;
    using Raven.Client.ServerWide;
    using Raven.Client.ServerWide.Operations;
    using Raven.Client.ServerWide.Operations.Configuration;
    using ServiceControl.Infrastructure.CustomIndexes;
    using ServiceControl.MessageFailures.Api;

    class DatabaseSetup(RavenPersisterSettings settings, IDocumentStore documentStore)
    {
        public async Task Execute(CancellationToken cancellationToken)
        {
            await CreateDatabase(settings.DatabaseName, cancellationToken);
            await CreateDatabase(settings.ThroughputDatabaseName, cancellationToken);

            await UpdateDatabaseSettings(settings.DatabaseName, cancellationToken);
            await UpdateDatabaseSettings(settings.ThroughputDatabaseName, cancellationToken);

            // Auto-discover and register all index-creation tasks in the assembly EXCEPT
            // FailedMessage_AttributesIndex, which has a parameterized ctor for config-driven
            // dynamic-field emission and is registered explicitly below.
            var indexes = DiscoverIndexTasks(typeof(DatabaseSetup).Assembly)
                .Where(i => i.GetType() != typeof(FailedMessage_AttributesIndex))
                .ToList();
            await IndexCreation.CreateIndexesAsync(indexes, documentStore, null, null, cancellationToken);

            // Custom-index spike: register the dynamic-field FailedMessage_AttributesIndex
            // with the active CustomIndexConfig's keys + version. Same version ⇒ no-op;
            // changed version ⇒ RavenDB builds a new index side-by-side without blocking
            // queries on the existing one.
            var customConfig = CustomIndexConfig.Active;
            if (customConfig.Indexes.Count > 0)
            {
                var attributesIndex = new FailedMessage_AttributesIndex(customConfig.Keys, customConfig.Version);
                await attributesIndex.ExecuteAsync(documentStore, null, null, cancellationToken);
            }

            await LicenseStatusCheck.WaitForLicenseOrThrow(documentStore, cancellationToken);
            await ConfigureExpiration(settings, cancellationToken);
        }

        // Mirrors the internal RavenDB GetAllInstancesOfType auto-discovery: any concrete
        // class derived from any index-creation base. The list is then filtered by the caller.
        static IEnumerable<AbstractIndexCreationTask> DiscoverIndexTasks(Assembly assembly)
        {
            foreach (var type in assembly.GetTypes())
            {
                if (type.IsAbstract)
                {
                    continue;
                }
                if (!typeof(AbstractIndexCreationTask).IsAssignableFrom(type))
                {
                    continue;
                }
                if (type.GetConstructor(Type.EmptyTypes) == null)
                {
                    continue;
                }
                yield return (AbstractIndexCreationTask)Activator.CreateInstance(type);
            }
        }

        async Task CreateDatabase(string databaseName, CancellationToken cancellationToken)
        {
            var dbRecord = await documentStore.Maintenance.Server.SendAsync(new GetDatabaseRecordOperation(databaseName), cancellationToken);

            if (dbRecord is null)
            {
                try
                {
                    var databaseRecord = new DatabaseRecord(databaseName);
                    databaseRecord.Settings.Add("Indexing.Auto.SearchEngineType", "Corax");
                    databaseRecord.Settings.Add("Indexing.Static.SearchEngineType", "Corax");

                    await documentStore.Maintenance.Server.SendAsync(new CreateDatabaseOperation(databaseRecord), cancellationToken);
                }
                catch (ConcurrencyException)
                {
                    // The database was already created before calling CreateDatabaseOperation
                }
            }
        }

        async Task UpdateDatabaseSettings(string databaseName, CancellationToken cancellationToken)
        {
            var dbRecord = await documentStore.Maintenance.Server.SendAsync(new GetDatabaseRecordOperation(databaseName), cancellationToken);

            if (dbRecord is null)
            {
                throw new InvalidOperationException($"Database '{databaseName}' does not exist.");
            }

            var updated = false;

            updated |= dbRecord.Settings.TryAdd("Indexing.Auto.SearchEngineType", "Corax");
            updated |= dbRecord.Settings.TryAdd("Indexing.Static.SearchEngineType", "Corax");

            if (updated)
            {
                await documentStore.Maintenance.ForDatabase(databaseName).SendAsync(new PutDatabaseSettingsOperation(databaseName, dbRecord.Settings), cancellationToken);
                await documentStore.Maintenance.Server.SendAsync(new ToggleDatabasesStateOperation(databaseName, true), cancellationToken);
                await documentStore.Maintenance.Server.SendAsync(new ToggleDatabasesStateOperation(databaseName, false), cancellationToken);
            }
        }

        async Task ConfigureExpiration(RavenPersisterSettings settings, CancellationToken cancellationToken)
        {
            var expirationConfig = new ExpirationConfiguration
            {
                Disabled = false,
                DeleteFrequencyInSec = settings.ExpirationProcessTimerInSeconds
            };

            await documentStore.Maintenance.SendAsync(new ConfigureExpirationOperation(expirationConfig), cancellationToken);
        }
    }
}