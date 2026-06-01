namespace ServiceControl.MessageFailures.Api
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Raven.Client.Documents.Indexes;

    /// <summary>
    /// Dynamic-field RavenDB index over <see cref="FailedMessage"/> that emits
    /// one <c>Attr_&lt;header&gt;</c> field per configured header key (e.g.
    /// <c>Attr_NServiceBus.Tenant</c>). The configured key list is captured at
    /// construction time and inlined into the index expression; changing it
    /// produces a new <see cref="AbstractIndexCreationTask.IndexName"/>, so
    /// RavenDB builds the new index side-by-side without blocking queries.
    /// </summary>
    /// <remarks>
    /// Not auto-discovered by <c>IndexCreation.CreateIndexesAsync(assembly, ...)</c>
    /// because the ctor takes a parameter. Registered explicitly by
    /// <c>DatabaseSetup</c> using the <c>CustomIndexConfig</c> loaded at startup.
    /// Query side: <c>session.Advanced.AsyncDocumentQuery&lt;Result, FailedMessage_AttributesIndex&gt;().WhereEquals("Attr_NServiceBus.Tenant", "acme")</c>.
    /// </remarks>
    public class FailedMessage_AttributesIndex : AbstractIndexCreationTask<FailedMessage>
    {
        readonly string version;

        public FailedMessage_AttributesIndex() : this(Array.Empty<string>(), "empty") { }

        public FailedMessage_AttributesIndex(string[] headerKeys, string version)
        {
            this.version = version;

            // Capture into a local so the lambda's serialized form inlines the array literal.
            var keys = headerKeys ?? Array.Empty<string>();

            Map = messages =>
                from m in messages
                let last = m.ProcessingAttempts.LastOrDefault()
                where last != null
                select new
                {
                    MessageId = m.Id,
                    m.Status,
                    // Dynamic-field emission: one Attr_<key> per configured key
                    // that's present in the last processing attempt's headers.
                    _ = keys
                        .Where(k => last.Headers.ContainsKey(k))
                        .Select(k => CreateField("Attr_" + k, last.Headers[k], stored: false, analyzed: false))
                };
        }

        // Versioned name so config changes trigger a side-by-side build.
        // Same keys ⇒ same version ⇒ same index ⇒ no rebuild.
        public override string IndexName => $"FailedMessage/Attributes/v{version}";

        /// <summary>Result projection — query against this to get back the doc id and status.</summary>
        public class Result
        {
            public string MessageId { get; set; }
            public FailedMessageStatus Status { get; set; }
        }
    }
}
