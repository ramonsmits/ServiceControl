﻿namespace ServiceControl.Operations
{
    using NServiceBus.CustomChecks;
    using NServiceBus.Logging;
    using Raven.Client;
    using System;

    class FailedAuditImportCustomCheck : CustomCheck
    {
        public FailedAuditImportCustomCheck(IDocumentStore store)
            : base("Audit Message Ingestion", "ServiceControl Health", TimeSpan.FromHours(1))
        {
            this.store = store;
        }

        public override CheckResult PerformCheck()
        {
            using (var session = store.OpenSession())
            {
                var query = session.Query<FailedAuditImport, FailedAuditImportIndex>();
                using (var ie = session.Advanced.Stream(query))
                {
                    if (ie.MoveNext())
                    {
                        var message = @"One or more audit messages have failed to import properly into ServiceControl and have been stored in the ServiceControl database.
The import of these messages could have failed for a number of reasons and ServiceControl is not able to automatically reimport them. For guidance on how to resolve this see https://docs.particular.net/servicecontrol/import-failed-audit-messages";

                        Logger.Warn(message);
                        return CheckResult.Failed(message);
                    }
                }
            }

            return CheckResult.Pass;
        }

        readonly IDocumentStore store;
        static readonly ILog Logger = LogManager.GetLogger(typeof(FailedAuditImportCustomCheck));
    }
}