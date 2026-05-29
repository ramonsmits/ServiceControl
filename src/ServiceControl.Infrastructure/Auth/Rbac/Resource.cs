#nullable enable
namespace ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Typed authorization resource. Subtype per resource category (queue, endpoint, …)
/// so call sites cannot accidentally pass the wrong kind of name. The scope-pattern
/// matching is on <see cref="Name"/>; the type tag is for compile-time safety and
/// future ABAC (Attribute-Based Access Control — which may carry additional attributes
/// per resource type).
/// </summary>
// add per resource category: EndpointResource, RecoverabilityGroupResource, etc. (Phase 2)
public abstract record Resource(string Name);

/// <summary>The receiving queue/endpoint address of a failed message.</summary>
public sealed record QueueResource(string Name) : Resource(Name);
