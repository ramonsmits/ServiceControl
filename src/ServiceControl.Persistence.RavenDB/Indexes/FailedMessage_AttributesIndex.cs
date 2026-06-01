namespace ServiceControl.MessageFailures.Api
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text.Json;
    using Raven.Client.Documents.Indexes;

    /// <summary>
    /// Dynamic-field RavenDB index over <see cref="FailedMessage"/> that emits
    /// one <c>Attr_&lt;header&gt;</c> field per configured header key (e.g.
    /// <c>Attr_NServiceBus.Tenant</c>). Implemented as a RAW JavaScript index so the
    /// configured key list can be inlined into the JS source string at construction
    /// time — RavenDB's C# index compiler doesn't handle closures over captured
    /// local arrays cleanly (the generated closure class isn't resolvable
    /// server-side).
    /// </summary>
    /// <remarks>
    /// The index name is versioned on a hash of the configured keys, so changing the
    /// extract-headers config produces a new index name and RavenDB builds the new
    /// index side-by-side without blocking queries on the existing one.
    /// Not auto-discovered by <c>IndexCreation.CreateIndexesAsync(assembly, ...)</c>
    /// because the ctor takes parameters. Registered explicitly by
    /// <c>DatabaseSetup</c> using the loaded <c>CustomIndexConfig</c>.
    /// </remarks>
    public class FailedMessage_AttributesIndex : AbstractJavaScriptIndexCreationTask
    {
        readonly string version;

        /// <summary>
        /// Parameterless ctor required only because <c>IndexCreation.CreateIndexesAsync(assembly,...)</c>
        /// reflects through the assembly and instantiates every index-task type with a default ctor.
        /// Produces a placeholder index name (<c>vunset</c>) that <c>DatabaseSetup</c> skips —
        /// the real registration happens explicitly with the keys + version loaded from <see cref="CustomIndexConfig"/>.
        /// </summary>
        public FailedMessage_AttributesIndex() : this(Array.Empty<string>(), "unset") { }

        public FailedMessage_AttributesIndex(string[] headerKeys, string version)
        {
            this.version = version;
            var keys = headerKeys ?? Array.Empty<string>();
            var keysJson = JsonSerializer.Serialize(keys);

            Maps =
            [
                $@"
map('FailedMessages', function (m) {{
    var attempts = m.ProcessingAttempts;
    var last = attempts && attempts.length > 0 ? attempts[attempts.length - 1] : null;
    if (!last) {{ return null; }}
    var headers = last.Headers || {{}};
    var keys = {keysJson};
    var doc = {{ MessageId: m['@metadata']['@id'], Status: m.Status }};
    for (var i = 0; i < keys.length; i++) {{
        var k = keys[i];
        if (headers.hasOwnProperty(k) && headers[k] !== null && headers[k] !== undefined) {{
            doc['Attr_' + k] = createField('Attr_' + k, headers[k], {{
                indexing: 'Exact', storage: 'No', termVector: 'No'
            }});
        }}
    }}
    return doc;
}})"
            ];
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
