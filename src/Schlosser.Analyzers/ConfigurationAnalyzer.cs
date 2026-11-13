using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser;

/// <summary>
/// SL031 to SL040: protections that were switched off or never switched on.
/// Certificate validation, TLS versions, deserialization, XML entities, token validation, cookies, CORS, anti-forgery,
/// secrets in logs, exception details in responses.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ConfigurationAnalyzer : DiagnosticAnalyzer
{
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(
        Rules.CertificateValidationDisabled, Rules.OldTlsVersion, Rules.InsecureDeserialization, Rules.Xxe, Rules.JwtValidationDisabled,
        Rules.CookieFlags, Rules.CorsAnyOrigin, Rules.AntiForgeryDisabled, Rules.SecretInLog, Rules.ExceptionDetails,
        Rules.WeakPasswordPolicy, Rules.NoLockout);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeLambda, OperationKind.AnonymousFunction);
        context.RegisterOperationAction(AnalyzeFieldReference, OperationKind.FieldReference);
        context.RegisterOperationAction(AnalyzePropertyReference, OperationKind.PropertyReference);
        context.RegisterOperationAction(AnalyzeCreation, OperationKind.ObjectCreation);
        context.RegisterOperationAction(AnalyzeAssignment, OperationKind.SimpleAssignment);
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
        context.RegisterSymbolAction(AnalyzeAttributes, SymbolKind.NamedType, SymbolKind.Method);
    }

    // ------------------------------------------------------------------ SL031 certificate validation

    private static void AnalyzeLambda(OperationAnalysisContext context)
    {
        var lambda = (IAnonymousFunctionOperation)context.Operation;
        if (!AlwaysReturnsTrue(lambda)) return;

        // What is the lambda used as? Either the delegate type says it, or the property it is assigned to.
        IOperation current = lambda;
        while (current.Parent is IDelegateCreationOperation or IConversionOperation or IParenthesizedOperation) current = current.Parent;

        var delegateType = current.Type?.Name;
        string? target = null;
        switch (current.Parent)
        {
            case IAssignmentOperation assignment when ReferenceEquals(assignment.Value, current):
                target = Names.Of(assignment.Target);
                break;
            case IArgumentOperation argument:
                target = argument.Parameter?.Name;
                break;
        }

        var isCertificateCallback = delegateType == "RemoteCertificateValidationCallback"
                                    || (target is not null && target.IndexOf("CertificateValidation", StringComparison.OrdinalIgnoreCase) >= 0)
                                    || (target is not null && target.IndexOf("CertificateCustomValidation", StringComparison.OrdinalIgnoreCase) >= 0);
        if (!isCertificateCallback) return;

        context.ReportDiagnostic(Diagnostic.Create(Rules.CertificateValidationDisabled, lambda.Syntax.GetLocation(),
            target is null ? "This callback" : "This " + target));
    }

    internal static bool AlwaysReturnsTrue(IAnonymousFunctionOperation lambda)
    {
        var returns = 0;
        foreach (var operation in lambda.Body.DescendantsAndSelf())
        {
            if (operation is IAnonymousFunctionOperation && !ReferenceEquals(operation, lambda)) return false;
            if (operation is not IReturnOperation returned) continue;
            if (returned.ReturnedValue?.ConstantValue is not { HasValue: true, Value: true }) return false;
            returns++;
        }

        return returns > 0;
    }

    private static void AnalyzePropertyReference(OperationAnalysisContext context)
    {
        var reference = (IPropertyReferenceOperation)context.Operation;
        if (reference.Property.Name == "DangerousAcceptAnyServerCertificateValidator")
        {
            context.ReportDiagnostic(Diagnostic.Create(Rules.CertificateValidationDisabled, reference.Syntax.GetLocation(),
                "DangerousAcceptAnyServerCertificateValidator"));
        }
    }

    // ------------------------------------------------------------------ SL032 TLS versions, SL033 TypeNameHandling

    private static void AnalyzeFieldReference(OperationAnalysisContext context)
    {
        var reference = (IFieldReferenceOperation)context.Operation;
        var field = reference.Field;
        var type = field.ContainingType;
        if (type is null || type.TypeKind != TypeKind.Enum) return;

        if (type.Name is "SslProtocols" or "SecurityProtocolType")
        {
            string? version = field.Name switch
            {
                "Ssl2" => "SSL 2.0",
                "Ssl3" => "SSL 3.0",
                "Tls" => "TLS 1.0",
                "Tls11" => "TLS 1.1",
                "Default" when type.Name == "SslProtocols" => "SSL 3.0 / TLS 1.0",
                _ => null,
            };
            if (version is not null)
                context.ReportDiagnostic(Diagnostic.Create(Rules.OldTlsVersion, reference.Syntax.GetLocation(), $"{type.Name}.{field.Name} ({version})"));
        }
    }

    // ------------------------------------------------------------------ object creations: SL033, SL036

    private static void AnalyzeCreation(OperationAnalysisContext context)
    {
        var creation = (IObjectCreationOperation)context.Operation;
        var type = creation.Type;
        if (type is null) return;

        switch (type.Name)
        {
            case "BinaryFormatter" when type.Is("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"):
            case "NetDataContractSerializer":
            case "SoapFormatter":
            case "LosFormatter":
            case "ObjectStateFormatter":
                context.ReportDiagnostic(Diagnostic.Create(Rules.InsecureDeserialization, creation.Syntax.GetLocation(),
                    type.Name + " creates whatever type the data names"));
                break;

            case "CookieOptions" when type.Is("Microsoft.AspNetCore.Http.CookieOptions"):
                CheckCookieOptions(context, creation);
                break;
        }
    }

    private static void CheckCookieOptions(OperationAnalysisContext context, IObjectCreationOperation creation)
    {
        // new CookieOptions(other) copies the flags of another instance
        if (creation.Arguments.Length > 0) return;

        var secure = false;
        var httpOnly = false;

        void Look(IOperation operation)
        {
            if (operation is not ISimpleAssignmentOperation { Target: IPropertyReferenceOperation target } assignment) return;
            if (target.Property.ContainingType?.Name != "CookieOptions") return;
            // Secure = true, or Secure = Request.IsHttps: a decision was made. An explicit "false" is reported at the assignment.
            if (target.Property.Name == "Secure") secure = true;
            if (target.Property.Name == "HttpOnly") httpOnly = true;
        }

        if (creation.Initializer is { } initializer)
            foreach (var member in initializer.Initializers) Look(member);

        // options.Secure = true; set later in the same method
        if (!secure || !httpOnly)
        {
            IOperation root = creation;
            while (root.Parent is not null) root = root.Parent;
            foreach (var operation in root.DescendantsAndSelf())
                if (operation.Parent is not IObjectOrCollectionInitializerOperation) Look(operation);
        }

        if (secure && httpOnly) return;
        var missing = !secure && !httpOnly ? "Secure and HttpOnly" : !secure ? "Secure" : "HttpOnly";
        var properties = ImmutableDictionary<string, string?>.Empty.Add("Missing", missing);
        context.ReportDiagnostic(Diagnostic.Create(Rules.CookieFlags, creation.Syntax.GetLocation(), properties,
            $"The cookie is created without {missing}: " + (!secure
                ? "it is also sent over plain HTTP" + (!httpOnly ? " and scripts can read it." : ".")
                : "scripts on the page can read it. If a script has to read this cookie, suppress this warning with a comment.")));
    }

    // ------------------------------------------------------------------ assignments: SL033, SL034, SL035, SL036, SL037

    private static void AnalyzeAssignment(OperationAnalysisContext context)
    {
        var assignment = (ISimpleAssignmentOperation)context.Operation;
        var value = assignment.Value;

        // response.Headers["Access-Control-Allow-Origin"] = Request.Headers["Origin"]
        if (assignment.Target is IPropertyReferenceOperation { Arguments.Length: 1 } indexer
            && indexer.Arguments[0].Value.ConstantValue is { HasValue: true, Value: string header }
            && header.Equals("Access-Control-Allow-Origin", StringComparison.OrdinalIgnoreCase)
            && !value.ConstantValue.HasValue
            && value.Syntax.ToString().IndexOf("Origin", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            context.ReportDiagnostic(Diagnostic.Create(Rules.CorsAnyOrigin, assignment.Syntax.GetLocation(),
                "The Origin header of the request is copied into Access-Control-Allow-Origin"));
            return;
        }

        if (assignment.Target is not IPropertyReferenceOperation { Property: { } property }) return;
        var type = property.ContainingType;
        if (type is null) return;
        var isFalse = value.ConstantValue is { HasValue: true, Value: false };

        switch (property.Name)
        {
            case "TypeNameHandling" when value.Unwrap() is IFieldReferenceOperation { Field.Name: not "None" } handling:
                if (!SiblingAssigns(assignment, "SerializationBinder") && !SiblingAssigns(assignment, "Binder"))
                    context.ReportDiagnostic(Diagnostic.Create(Rules.InsecureDeserialization, assignment.Syntax.GetLocation(),
                        $"TypeNameHandling.{handling.Field.Name} without a SerializationBinder lets the JSON name the types to create"));
                break;

            case "DtdProcessing" when value.Unwrap() is IFieldReferenceOperation { Field.Name: "Parse" }:
                context.ReportDiagnostic(Diagnostic.Create(Rules.Xxe, assignment.Syntax.GetLocation(), "DtdProcessing.Parse"));
                break;

            case "ProhibitDtd" when isFalse:
                context.ReportDiagnostic(Diagnostic.Create(Rules.Xxe, assignment.Syntax.GetLocation(), "ProhibitDtd = false"));
                break;

            case "XmlResolver" when type.ContainingNamespace?.ToDisplayString().StartsWith("System.Xml", StringComparison.Ordinal) == true
                                    && value.Unwrap() is IObjectCreationOperation { Type.Name: "XmlUrlResolver" }:
                context.ReportDiagnostic(Diagnostic.Create(Rules.Xxe, assignment.Syntax.GetLocation(), "An XmlUrlResolver"));
                break;

            case "ValidateIssuer" or "ValidateAudience" or "ValidateLifetime" or "RequireSignedTokens" or "RequireExpirationTime"
                when isFalse && type.Name == "TokenValidationParameters":
            {
                var consequence = property.Name switch
                {
                    "ValidateIssuer" => "tokens from any issuer are accepted",
                    "ValidateAudience" => "tokens issued for a different API are accepted",
                    "ValidateLifetime" => "expired tokens are accepted forever",
                    "RequireSignedTokens" => "unsigned tokens (alg: none) are accepted, so anyone can forge one",
                    _ => "tokens without an expiry are accepted",
                };
                context.ReportDiagnostic(Diagnostic.Create(Rules.JwtValidationDisabled, assignment.Syntax.GetLocation(), property.Name, "false", consequence));
                break;
            }

            case "RequireHttpsMetadata" when isFalse:
                context.ReportDiagnostic(Diagnostic.Create(Rules.JwtValidationDisabled, assignment.Syntax.GetLocation(), property.Name, "false",
                    "the signing keys are fetched over plain HTTP, where they can be replaced"));
                break;

            case "SignatureValidator" when type.Name == "TokenValidationParameters" && value.Unwrap() is not ILiteralOperation:
                context.ReportDiagnostic(Diagnostic.Create(Rules.JwtValidationDisabled, assignment.Syntax.GetLocation(), property.Name, "a custom delegate",
                    "the signature check of the library is replaced; a delegate that only reads the token accepts forged ones"));
                break;

            case "RequiredLength" when type.Name == "PasswordOptions" && value.ConstantValue is { HasValue: true, Value: int length } && length < 8:
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordPolicy, assignment.Syntax.GetLocation(), length));
                break;

            case "AllowedForNewUsers" when isFalse && type.Name == "LockoutOptions":
                context.ReportDiagnostic(Diagnostic.Create(Rules.NoLockout, assignment.Syntax.GetLocation(),
                    "Lockout.AllowedForNewUsers = false: new accounts are never locked"));
                break;

            case "HttpOnly" when isFalse && type.Name is "CookieBuilder" or "CookieOptions":
                context.ReportDiagnostic(Diagnostic.Create(Rules.CookieFlags, assignment.Syntax.GetLocation(),
                    "HttpOnly = false: scripts on the page can read this cookie."));
                break;

            case "Secure" when isFalse && type.Name == "CookieOptions":
                context.ReportDiagnostic(Diagnostic.Create(Rules.CookieFlags, assignment.Syntax.GetLocation(),
                    "Secure = false: the cookie is also sent over plain HTTP."));
                break;

            case "SecurePolicy" when type.Name == "CookieBuilder" && value.Unwrap() is IFieldReferenceOperation { Field.Name: "None" }:
                context.ReportDiagnostic(Diagnostic.Create(Rules.CookieFlags, assignment.Syntax.GetLocation(),
                    "CookieSecurePolicy.None: the cookie is also sent over plain HTTP."));
                break;
        }
    }

    private static bool SiblingAssigns(IOperation assignment, string propertyName)
    {
        if (assignment.Parent is not IObjectOrCollectionInitializerOperation initializer) return false;
        return initializer.Initializers.Any(i => i is ISimpleAssignmentOperation { Target: IPropertyReferenceOperation target } && target.Property.Name == propertyName);
    }

    // ------------------------------------------------------------------ invocations: SL036, SL037, SL038, SL039, SL040

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;
        var type = method.ContainingType;
        if (type is null) return;

        switch (method.Name)
        {
            case "Append" when type.Name == "IResponseCookies" && method.Parameters.Length == 2:
                context.ReportDiagnostic(Diagnostic.Create(Rules.CookieFlags, invocation.Syntax.GetLocation(),
                    "The cookie is set without CookieOptions, so without Secure, HttpOnly and SameSite."));
                return;

            case "SetIsOriginAllowed" when type.Name == "CorsPolicyBuilder":
                if (invocation.Arguments.Length == 1 && LambdaOf(invocation.Arguments[0].Value) is { } lambda && AlwaysReturnsTrue(lambda)
                    && ScopeCalls(invocation, "AllowCredentials"))
                    context.ReportDiagnostic(Diagnostic.Create(Rules.CorsAnyOrigin, NameLocation(invocation),
                        "SetIsOriginAllowed accepts every origin and AllowCredentials is on"));
                return;

            case "AllowAnyOrigin" when type.Name == "CorsPolicyBuilder":
                if (ScopeCalls(invocation, "AllowCredentials"))
                    context.ReportDiagnostic(Diagnostic.Create(Rules.CorsAnyOrigin, NameLocation(invocation),
                        "AllowAnyOrigin is combined with AllowCredentials"));
                return;

            case "PasswordSignInAsync" or "CheckPasswordSignInAsync" when type.Name == "SignInManager":
                foreach (var argument in invocation.Arguments)
                {
                    if (argument.Parameter?.Name == "lockoutOnFailure" && argument.Value.ConstantValue is { HasValue: true, Value: false })
                        context.ReportDiagnostic(Diagnostic.Create(Rules.NoLockout, argument.Value.Syntax.GetLocation(),
                            "lockoutOnFailure: false does not count failed sign-ins"));
                }
                return;

            case "DisableAntiforgery":
                // A handler that validates the token itself (IAntiforgery.IsRequestValidAsync) has not lost the protection
                if (invocation.DescendantsAndSelf().Any(o => o is IInvocationOperation { TargetMethod.Name: "IsRequestValidAsync" or "ValidateRequestAsync" }))
                    return;
                context.ReportDiagnostic(Diagnostic.Create(Rules.AntiForgeryDisabled, NameLocation(invocation), "DisableAntiforgery()"));
                return;

            case "UseDeveloperExceptionPage":
                if (!InsideDevelopmentCheck(invocation))
                    context.ReportDiagnostic(Diagnostic.Create(Rules.ExceptionDetails, NameLocation(invocation),
                        "UseDeveloperExceptionPage outside of an IsDevelopment() check"));
                return;
        }

        if (IsLogCall(method)) CheckLogArguments(context, invocation);
        else if (IsResponse(method)) CheckExceptionInResponse(context, invocation);
    }

    /// <summary>The method name of a fluent call, so that a ten-line chain is not underlined as a whole.</summary>
    private static Location NameLocation(IInvocationOperation invocation) =>
        invocation.Syntax is Microsoft.CodeAnalysis.CSharp.Syntax.InvocationExpressionSyntax
        {
            Expression: Microsoft.CodeAnalysis.CSharp.Syntax.MemberAccessExpressionSyntax member
        }
            ? member.Name.GetLocation()
            : invocation.Syntax.GetLocation();

    private static IAnonymousFunctionOperation? LambdaOf(IOperation value)
    {
        value = value.Unwrap();
        if (value is IDelegateCreationOperation creation) value = creation.Target.Unwrap();
        return value as IAnonymousFunctionOperation;
    }

    /// <summary>Is a method with this name called in the same lambda or method body (the CORS policy being configured)?</summary>
    private static bool ScopeCalls(IOperation operation, string methodName)
    {
        IOperation scope = operation;
        while (scope.Parent is not null && scope is not IAnonymousFunctionOperation) scope = scope.Parent;
        return scope.DescendantsAndSelf().Any(o => o is IInvocationOperation invocation && invocation.TargetMethod.Name == methodName);
    }

    private static bool InsideDevelopmentCheck(IOperation operation)
    {
        for (var parent = operation.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent is IConditionalOperation conditional
                && conditional.Condition.Syntax.ToString().IndexOf("Development", StringComparison.Ordinal) >= 0)
                return true;
        }

        return false;
    }

    // ------------------------------------------------------------------ SL039 secrets in logs

    private static bool IsLogCall(IMethodSymbol method)
    {
        var type = method.ContainingType;
        if (type.Name == "LoggerExtensions" && method.Name.StartsWith("Log", StringComparison.Ordinal)) return true;
        var ns = type.ContainingNamespace?.ToDisplayString() ?? "";
        if (ns == "Serilog" && type.Name is "Log" or "ILogger") return true;
        if (ns == "NLog" && type.Name is "Logger" or "ILogger") return true;
        return type.SpecialType == SpecialType.None && type.Is("System.Console") && method.Name is "WriteLine" or "Write";
    }

    private static void CheckLogArguments(OperationAnalysisContext context, IInvocationOperation invocation)
    {
        foreach (var argument in invocation.Arguments)
        {
            if (argument.Parameter is null) continue;
            if (argument.Parameter.Type.Name is "ILogger" or "EventId" or "LogLevel" or "Exception") continue;
            foreach (var value in LoggedValues(argument.Value))
            {
                if (value.ConstantValue.HasValue) continue;
                var type = value.Unwrap().Type;
                if (type is null || type.SpecialType is not (SpecialType.System_String or SpecialType.System_Object) && type.Name != "StringValues") continue;
                var name = Names.Of(value);
                if (!Names.IsLoggedSecret(name)) continue;
                context.ReportDiagnostic(Diagnostic.Create(Rules.SecretInLog, value.Syntax.GetLocation(), name));
            }
        }
    }

    /// <summary>The values that end up in the log line: params array elements, interpolation holes, concatenation operands.</summary>
    private static System.Collections.Generic.IEnumerable<IOperation> LoggedValues(IOperation value)
    {
        value = value.Unwrap();
        switch (value)
        {
            case IArrayCreationOperation { Initializer: { } initializer }:
                foreach (var element in initializer.ElementValues)
                foreach (var nested in LoggedValues(element)) yield return nested;
                break;
            case IInterpolatedStringOperation interpolated:
                foreach (var part in interpolated.Parts)
                    if (part is IInterpolationOperation interpolation)
                        foreach (var nested in LoggedValues(interpolation.Expression)) yield return nested;
                break;
            case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add } binary:
                foreach (var nested in LoggedValues(binary.LeftOperand)) yield return nested;
                foreach (var nested in LoggedValues(binary.RightOperand)) yield return nested;
                break;
            default:
                yield return value;
                break;
        }
    }

    // ------------------------------------------------------------------ SL040 exception details

    private static bool IsResponse(IMethodSymbol method)
    {
        var type = method.ContainingType;
        if (type.Name is "Results" or "TypedResults" && type.ContainingNamespace?.ToDisplayString() == "Microsoft.AspNetCore.Http") return true;
        if (type.Name == "HttpResponseWritingExtensions") return true;
        if (!type.InheritsFrom("Microsoft.AspNetCore.Mvc.ControllerBase") && !type.InheritsFrom("Microsoft.AspNetCore.Mvc.RazorPages.PageModel")) return false;
        return method.ReturnType.IsOrImplements("Microsoft.AspNetCore.Mvc.IActionResult")
               || method.ReturnType.IsOrImplements("Microsoft.AspNetCore.Http.IResult");
    }

    private static void CheckExceptionInResponse(OperationAnalysisContext context, IInvocationOperation invocation)
    {
        foreach (var argument in invocation.Arguments)
        {
            // Ok(ex), StatusCode(500, ex): the whole exception is serialized
            if (argument.Value.Unwrap() is ILocalReferenceOperation or IParameterReferenceOperation && IsException(argument.Value.Unwrap().Type))
            {
                context.ReportDiagnostic(Diagnostic.Create(Rules.ExceptionDetails, argument.Value.Unwrap().Syntax.GetLocation(), "The exception object"));
                return;
            }

            foreach (var operation in argument.Value.DescendantsAndSelf())
            {
                if (operation is IAnonymousFunctionOperation) break;
                var leak = ExceptionLeak(operation);
                if (leak is null) continue;
                context.ReportDiagnostic(Diagnostic.Create(Rules.ExceptionDetails, operation.Syntax.GetLocation(), leak));
                return;
            }
        }
    }

    private static string? ExceptionLeak(IOperation operation)
    {
        switch (operation)
        {
            case IPropertyReferenceOperation { Instance: { } instance } property when IsException(instance.Type):
                if (property.Property.Name == "StackTrace") return "The stack trace";
                // The message of a specific exception type is often written for the user; the message of "any exception" is not
                if (property.Property.Name == "Message" && instance.Type.Is("System.Exception")) return "The message of an unexpected exception";
                return null;
            case IInvocationOperation { Instance: { } instance, TargetMethod.Name: "ToString" } when IsException(instance.Type):
                return "Exception.ToString()";
            default:
                return null;
        }
    }

    private static bool IsException(ITypeSymbol? type) => type.InheritsFrom("System.Exception");

    // ------------------------------------------------------------------ SL038 [IgnoreAntiforgeryToken]

    private static void AnalyzeAttributes(SymbolAnalysisContext context)
    {
        foreach (var attribute in context.Symbol.GetAttributes())
        {
            if (attribute.AttributeClass?.Name != "IgnoreAntiforgeryTokenAttribute") continue;
            if (attribute.ApplicationSyntaxReference?.GetSyntax(context.CancellationToken) is { } syntax)
                context.ReportDiagnostic(Diagnostic.Create(Rules.AntiForgeryDisabled, syntax.GetLocation(), "[IgnoreAntiforgeryToken]"));
        }
    }
}
