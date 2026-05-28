#nullable enable
namespace ServiceControl.Infrastructure.WebApi.Auth;

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Casbin;
using Casbin.Model;
using Casbin.Persist.Adapter.Text;
using ServiceControl.Infrastructure.Auth.Rbac;

/// <summary>
/// Creates and configures the Casbin <see cref="IEnforcer"/> singleton for the S4 variant.
///
/// <para>
/// The model (<c>rbac.model.conf</c>) is embedded in the assembly so it ships with the binary
/// and cannot be tampered with by operators. The policy is compiled at runtime from the
/// operator-editable <c>rbac.yaml</c> via <see cref="RbacPolicyToCasbinCompiler"/> — operators
/// continue to edit YAML; they never need to understand Casbin syntax.
/// </para>
///
/// <para>
/// The enforcer is built once at startup (singleton). Policy reload is a future enhancement
/// that would rebuild the enforcer from a freshly loaded policy.
/// </para>
/// </summary>
public static class CasbinEnforcerFactory
{
    /// <summary>
    /// The resource name of the embedded Casbin model file.
    /// </summary>
    const string ModelResourceName = "ServiceControl.rbac.model.conf";

    /// <summary>
    /// Builds a configured <see cref="IEnforcer"/> from the embedded model and the
    /// compiled policy derived from <paramref name="rbacPolicy"/>.
    /// </summary>
    /// <param name="rbacPolicy">The policy loaded from <c>rbac.yaml</c>.</param>
    /// <returns>A ready-to-use Casbin enforcer.</returns>
    public static IEnforcer Build(RbacPolicy rbacPolicy)
    {
        var model = LoadModelFromEmbeddedResource();
        var policyLines = RbacPolicyToCasbinCompiler.Compile(rbacPolicy);
        var policyText = string.Join("\n", policyLines);
        var adapter = new TextAdapter(policyText);

        var enforcer = new Enforcer(model, adapter);
        return enforcer;
    }

    /// <summary>
    /// Loads the Casbin model from the embedded <c>rbac.model.conf</c> resource.
    /// </summary>
    static IModel LoadModelFromEmbeddedResource()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(ModelResourceName)
            ?? throw new InvalidOperationException(
                $"Embedded Casbin model resource '{ModelResourceName}' not found. " +
                $"Available resources: {string.Join(", ", assembly.GetManifestResourceNames())}");

        using var reader = new StreamReader(stream);
        var modelText = reader.ReadToEnd();

        var model = DefaultModel.Create();
        model.LoadModelFromText(modelText);
        return model;
    }
}
