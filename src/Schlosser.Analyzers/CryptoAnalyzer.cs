using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser;

/// <summary>SL020 to SL025: broken algorithms, predictable random numbers, hard-coded keys, weak password hashing, timing leaks.</summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CryptoAnalyzer : DiagnosticAnalyzer
{
    private const string Crypto = "System.Security.Cryptography";
    public const int MinimumPbkdf2Iterations = 100_000;

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(
        Rules.WeakHash, Rules.WeakCipher, Rules.InsecureRandom, Rules.HardCodedKey, Rules.WeakPasswordHash, Rules.TimingComparison);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
        context.RegisterOperationAction(AnalyzeCreation, OperationKind.ObjectCreation);
        context.RegisterOperationAction(AnalyzeFieldReference, OperationKind.FieldReference);
        context.RegisterOperationAction(AnalyzePropertyReference, OperationKind.PropertyReference);
        context.RegisterOperationAction(AnalyzeAssignment, OperationKind.SimpleAssignment);
        context.RegisterOperationAction(AnalyzeComparison, OperationKind.Binary);
    }

    private static bool InCrypto(ISymbol? symbol) => symbol?.ContainingNamespace?.ToDisplayString() == Crypto;

    // ------------------------------------------------------------------ invocations

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;
        var type = method.ContainingType;
        if (type is null) return;

        if (InCrypto(type))
        {
            // A password under a fast hash is the bigger problem and gets its own message (SL024) instead of SL020
            var hashesPassword = method.Name is "HashData" or "ComputeHash" or "TryHashData" && invocation.Arguments.Length > 0
                                 && IsPlainHash(invocation.Instance?.Type as INamedTypeSymbol ?? type)
                                 && PasswordIn(invocation.Arguments[0].Value) is not null;

            if (method.IsStatic && method.Name is "Create" or "HashData" or "HashDataAsync" or "TryHashData")
            {
                if (hashesPassword) { }
                else if (WeakHashName(type.Name) is { } hash)
                    context.ReportDiagnostic(Diagnostic.Create(Rules.WeakHash, invocation.Syntax.GetLocation(), Properties("Type", type.Name), hash));
                else if (WeakCipherName(type.Name) is { } cipher)
                    context.ReportDiagnostic(Diagnostic.Create(Rules.WeakCipher, invocation.Syntax.GetLocation(), cipher + " is an obsolete cipher"));
            }

            if (method.Name is "EncryptEcb" or "DecryptEcb" or "TryEncryptEcb" or "TryDecryptEcb")
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakCipher, invocation.Syntax.GetLocation(),
                    "ECB mode encrypts equal blocks to equal ciphertext, which shows patterns of the data"));

            // SHA256.HashData(Encoding.UTF8.GetBytes(password)): one round of a fast hash
            if (method.Name is "HashData" or "ComputeHash" or "TryHashData" && invocation.Arguments.Length > 0
                && IsPlainHash(invocation.Instance?.Type as INamedTypeSymbol ?? type)
                && PasswordIn(invocation.Arguments[0].Value) is { } password)
            {
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordHash, invocation.Syntax.GetLocation(),
                    $"'{password}' is hashed with a single round of {HashDisplayName(invocation, type)}, which is made to be fast"));
            }

            if (type.Name == "Rfc2898DeriveBytes" && method.Name == "Pbkdf2") CheckPbkdf2(context, invocation.Arguments, invocation.Syntax.GetLocation(), hasDefaults: false);

            CheckKeyArguments(context, invocation.Arguments);
        }
        else if (type.Name == "KeyDerivation" && method.Name == "Pbkdf2")
        {
            CheckPbkdf2(context, invocation.Arguments, invocation.Syntax.GetLocation(), hasDefaults: false);
        }
        else if (type.Is("System.Random"))
        {
            CheckRandom(context, invocation);
        }
        else if (method.Name == "SequenceEqual" && invocation.Arguments.Length == 2
                 && type.Name is "Enumerable" or "MemoryExtensions")
        {
            CheckTiming(context, invocation, invocation.Arguments[0].Value, invocation.Arguments[1].Value, "SequenceEqual");
        }
        else if (method.Name == "Equals" && type.SpecialType == SpecialType.System_String)
        {
            if (method.IsStatic && invocation.Arguments.Length >= 2)
                CheckTiming(context, invocation, invocation.Arguments[0].Value, invocation.Arguments[1].Value, "string.Equals");
            else if (!method.IsStatic && invocation.Instance is not null && invocation.Arguments.Length >= 1)
                CheckTiming(context, invocation, invocation.Instance, invocation.Arguments[0].Value, "Equals");
        }
    }

    private static void AnalyzeCreation(OperationAnalysisContext context)
    {
        var creation = (IObjectCreationOperation)context.Operation;
        var type = creation.Type;
        if (type is null) return;

        if (InCrypto(type))
        {
            if (WeakHashName(type.Name) is { } hash)
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakHash, creation.Syntax.GetLocation(), Properties("Type", type.Name), hash));
            else if (WeakCipherName(type.Name) is { } cipher)
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakCipher, creation.Syntax.GetLocation(), cipher + " is an obsolete cipher"));

            if (type.Name == "Rfc2898DeriveBytes") CheckPbkdf2(context, creation.Arguments, creation.Syntax.GetLocation(), hasDefaults: true);
            CheckKeyArguments(context, creation.Arguments);
        }
        else if (type.Name == "SymmetricSecurityKey" && creation.Arguments.Length == 1 && IsLiteralBytes(creation.Arguments[0].Value))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rules.HardCodedKey, creation.Arguments[0].Value.Syntax.GetLocation(), "signing key"));
        }
    }

    private static string? WeakHashName(string typeName)
    {
        switch (typeName)
        {
            case "MD5":
            case "MD5CryptoServiceProvider":
            case "MD5Cng":
                return "MD5";
            case "HMACMD5":
                return "HMAC-MD5";
            case "SHA1":
            case "SHA1CryptoServiceProvider":
            case "SHA1Managed":
            case "SHA1Cng":
                return "SHA-1";
            default:
                return null; // HMACSHA1 is not reported: it is still sound and required by TOTP (RFC 6238)
        }
    }

    private static string? WeakCipherName(string typeName)
    {
        switch (typeName)
        {
            case "DES":
            case "DESCryptoServiceProvider":
                return "DES";
            case "TripleDES":
            case "TripleDESCryptoServiceProvider":
            case "TripleDESCng":
                return "Triple DES";
            case "RC2":
            case "RC2CryptoServiceProvider":
                return "RC2";
            default:
                return null;
        }
    }

    // ------------------------------------------------------------------ enum members and static properties

    private static void AnalyzeFieldReference(OperationAnalysisContext context)
    {
        var reference = (IFieldReferenceOperation)context.Operation;
        var field = reference.Field;
        if (field.Name == "ECB" && field.ContainingType.Is(Crypto + ".CipherMode"))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rules.WeakCipher, reference.Syntax.GetLocation(),
                "ECB mode encrypts equal blocks to equal ciphertext, which shows patterns of the data"));
        }
        else if (field.Name == "HMACSHA1" && field.ContainingType?.Name == "KeyDerivationPrf")
        {
            context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordHash, reference.Syntax.GetLocation(), "PBKDF2 with HMAC-SHA1"));
        }
    }

    private static void AnalyzePropertyReference(OperationAnalysisContext context)
    {
        var reference = (IPropertyReferenceOperation)context.Operation;
        var property = reference.Property;

        if (property.ContainingType.Is(Crypto + ".HashAlgorithmName") && property.Name is "MD5" or "SHA1")
        {
            // What it is used for decides: HMAC-SHA1 in TOTP is fine, a SHA-1 signature or PBKDF2-SHA1 is not
            var user = (reference.Parent as IArgumentOperation)?.Parent switch
            {
                IInvocationOperation invocation => invocation.TargetMethod,
                IObjectCreationOperation creation => creation.Constructor,
                _ => null,
            };
            if (user is null) return;
            var display = property.Name == "MD5" ? "MD5" : "SHA-1";

            if (user.ContainingType?.Name == "Rfc2898DeriveBytes")
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordHash, reference.Syntax.GetLocation(), "PBKDF2 with " + display));
            else if (user.Name.Contains("Sign") || user.Name.Contains("Verify") || property.Name == "MD5")
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakHash, reference.Syntax.GetLocation(), display + " in a signature"));
        }
    }

    // ------------------------------------------------------------------ SL022 System.Random

    private static void CheckRandom(OperationAnalysisContext context, IInvocationOperation invocation)
    {
        var method = invocation.TargetMethod;
        if (method.IsStatic || !method.Name.StartsWith("Next") && method.Name is not ("GetItems" or "GetString" or "GetHexString" or "Shuffle")) return;

        // Where does the random value go? The variable it is stored in, then the method and the type around it.
        var receiver = Names.Receiver(invocation);
        var (enclosingMethod, enclosingType) = Names.Enclosing(invocation, context.ContainingSymbol);

        string? purpose = null;
        if (Names.NeedsCryptoRandom(receiver)) purpose = receiver;
        else if (invocation.Arguments.Length > 0 && Names.NeedsCryptoRandom(Names.Of(invocation.Arguments[0].Value))) purpose = Names.Of(invocation.Arguments[0].Value);
        else if (Names.NeedsCryptoRandom(enclosingMethod)) purpose = enclosingMethod;
        else if (Names.NeedsCryptoRandom(enclosingType)) purpose = enclosingType;
        if (purpose is null) return;

        context.ReportDiagnostic(Diagnostic.Create(Rules.InsecureRandom, invocation.Syntax.GetLocation(), "'" + purpose + "'"));
    }

    // ------------------------------------------------------------------ SL023 hard-coded keys

    private static void AnalyzeAssignment(OperationAnalysisContext context)
    {
        var assignment = (ISimpleAssignmentOperation)context.Operation;
        if (assignment.Target is not IPropertyReferenceOperation { Property: { } property }) return;
        if (property.Name is not ("Key" or "IV")) return;
        if (!property.ContainingType.InheritsFrom(Crypto + ".SymmetricAlgorithm")) return;

        if (IsLiteralBytes(assignment.Value) || (property.Name == "IV" && IsZeroBytes(assignment.Value)))
            context.ReportDiagnostic(Diagnostic.Create(Rules.HardCodedKey, assignment.Value.Syntax.GetLocation(), property.Name == "IV" ? "IV" : "key"));
    }

    private static void CheckKeyArguments(OperationAnalysisContext context, ImmutableArray<IArgumentOperation> arguments)
    {
        foreach (var argument in arguments)
        {
            string? what = argument.Parameter?.Name switch
            {
                "key" or "rgbKey" => "key",
                "iv" or "rgbIV" => "IV",
                "salt" or "rgbSalt" => "salt",
                "nonce" => "nonce",
                _ => null,
            };
            if (what is null || argument.IsImplicit) continue;
            if (IsLiteralBytes(argument.Value) || (what is "IV" or "nonce" && IsZeroBytes(argument.Value)))
                context.ReportDiagnostic(Diagnostic.Create(Rules.HardCodedKey, argument.Value.Syntax.GetLocation(), what));
        }
    }

    /// <summary>Bytes that are written in the source: a byte array literal, or the bytes of a string literal.</summary>
    private static bool IsLiteralBytes(IOperation? value, int depth = 0)
    {
        value = value?.Unwrap();
        switch (value)
        {
            case IArrayCreationOperation { Initializer: { } initializer } array
                when array.Type is IArrayTypeSymbol { ElementType.SpecialType: SpecialType.System_Byte }:
                return initializer.ElementValues.Length >= 4 && initializer.ElementValues.All(e => e.ConstantValue.HasValue);

            case IInvocationOperation invocation:
            {
                var name = invocation.TargetMethod.Name;
                if (name is "GetBytes" or "FromBase64String" or "FromHexString" && invocation.Arguments.Length >= 1)
                    return invocation.Arguments[0].Value.ConstantValue is { HasValue: true, Value: string { Length: > 0 } };
                return false;
            }

            // a local or field that holds literal bytes
            case ILocalReferenceOperation local when depth < 3:
                return InitializerOf(local.Local, value) is { } localValue && IsLiteralBytes(localValue, depth + 1);
            case IFieldReferenceOperation field when depth < 3:
                return InitializerOf(field.Field, value) is { } fieldValue && IsLiteralBytes(fieldValue, depth + 1);

            default:
                return false;
        }
    }

    /// <summary>new byte[16]: an all-zero IV.</summary>
    private static bool IsZeroBytes(IOperation? value)
    {
        return value?.Unwrap() is IArrayCreationOperation { Initializer: null } array
               && array.Type is IArrayTypeSymbol { ElementType.SpecialType: SpecialType.System_Byte }
               && array.DimensionSizes.Length == 1 && array.DimensionSizes[0].ConstantValue.HasValue;
    }

    private static IOperation? InitializerOf(ISymbol symbol, IOperation usedAt)
    {
        var model = usedAt.SemanticModel;
        if (model is null) return null;
        foreach (var reference in symbol.DeclaringSyntaxReferences)
        {
            if (reference.SyntaxTree != model.SyntaxTree) continue; // only the same file: no extra semantic models
            var operation = model.GetOperation(reference.GetSyntax());
            switch (operation)
            {
                case IVariableDeclaratorOperation { Initializer: { } initializer }: return initializer.Value;
                case IVariableDeclaratorOperation { Parent: IVariableDeclarationOperation { Initializer: { } shared } }: return shared.Value;
                case IFieldInitializerOperation fieldInitializer: return fieldInitializer.Value;
            }

            // for fields GetOperation on the declarator returns null: ask for the "= value" part instead
            if (reference.GetSyntax() is Microsoft.CodeAnalysis.CSharp.Syntax.VariableDeclaratorSyntax { Initializer: { } equals })
            {
                if (model.GetOperation(equals) is ISymbolInitializerOperation symbolInitializer) return symbolInitializer.Value;
                return model.GetOperation(equals.Value);
            }
        }

        return null;
    }

    // ------------------------------------------------------------------ SL024 password hashing

    private static void CheckPbkdf2(OperationAnalysisContext context, ImmutableArray<IArgumentOperation> arguments, Location location, bool hasDefaults)
    {
        IArgumentOperation? iterations = null;
        var hasAlgorithm = false;
        foreach (var argument in arguments)
        {
            if (argument.IsImplicit) continue;
            if (argument.Parameter?.Name is "iterations" or "iterationCount") iterations = argument;
            if (argument.Parameter?.Name is "hashAlgorithm" or "prf") hasAlgorithm = true;
        }

        if (iterations is null)
        {
            if (hasDefaults)
                context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordHash, location, "Rfc2898DeriveBytes without an iteration count uses 1,000 rounds of SHA-1"));
            return;
        }

        if (iterations.Value.ConstantValue is { HasValue: true, Value: int count } && count < MinimumPbkdf2Iterations)
            context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordHash, iterations.Value.Syntax.GetLocation(), "PBKDF2 with only " + count.ToString("N0", System.Globalization.CultureInfo.InvariantCulture) + " iterations"));
        else if (hasDefaults && !hasAlgorithm)
            context.ReportDiagnostic(Diagnostic.Create(Rules.WeakPasswordHash, location, "Rfc2898DeriveBytes without a hash algorithm uses SHA-1"));
    }

    private static bool IsPlainHash(INamedTypeSymbol type)
    {
        // SHA256, SHA512, MD5 ... but not HMAC (keyed) and not the PBKDF2 classes
        if (!type.InheritsFrom(Crypto + ".HashAlgorithm")) return false;
        return !type.InheritsFrom(Crypto + ".KeyedHashAlgorithm");
    }

    private static string HashDisplayName(IInvocationOperation invocation, INamedTypeSymbol type)
    {
        var name = type.Name == "HashAlgorithm" ? invocation.Instance?.Type?.Name ?? "a hash" : type.Name;
        return name.StartsWith("SHA") && name.Length > 3 && char.IsDigit(name[3]) ? "SHA-" + name.Substring(3) : name;
    }

    private static string? PasswordIn(IOperation value)
    {
        foreach (var operation in value.DescendantsAndSelf())
        {
            var name = operation switch
            {
                ILocalReferenceOperation local => local.Local.Name,
                IParameterReferenceOperation parameter => parameter.Parameter.Name,
                IMemberReferenceOperation member => member.Member.Name,
                _ => null,
            };
            if (name is null) continue;
            var words = Names.Words(name);
            if (words.Count == 0) continue;
            if (words[words.Count - 1] is "password" or "passwort" or "kennwort" or "passwd" or "pwd" or "passphrase") return name;
        }

        return null;
    }

    // ------------------------------------------------------------------ SL025 timing

    private static void AnalyzeComparison(OperationAnalysisContext context)
    {
        var binary = (IBinaryOperation)context.Operation;
        if (binary.OperatorKind is not (BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals)) return;
        if (binary.LeftOperand.Type?.SpecialType != SpecialType.System_String || binary.RightOperand.Type?.SpecialType != SpecialType.System_String) return;
        CheckTiming(context, binary, binary.LeftOperand, binary.RightOperand, binary.OperatorKind == BinaryOperatorKind.Equals ? "==" : "!=");
    }

    private static void CheckTiming(OperationAnalysisContext context, IOperation comparison, IOperation left, IOperation right, string how)
    {
        if (IsConstantLike(left) || IsConstantLike(right)) return;
        if (!IsTextOrBytes(left.Unwrap().Type) || !IsTextOrBytes(right.Unwrap().Type)) return;

        var leftName = Names.Of(left);
        var rightName = Names.Of(right);
        var secret = Names.IsComparedSecret(leftName) ? leftName : Names.IsComparedSecret(rightName) ? rightName : null;
        if (secret is null) return;

        // db.Tokens.Where(t => t.Token == token) is translated to SQL: the database compares, not this code
        for (var parent = comparison.Parent; parent is not null; parent = parent.Parent)
        {
            if (parent is IAnonymousFunctionOperation && parent.Parent is { Type.Name: "Expression" } or IDelegateCreationOperation { Parent.Type.Name: "Expression" })
                return;
        }

        context.ReportDiagnostic(Diagnostic.Create(Rules.TimingComparison, comparison.Syntax.GetLocation(), secret, how));
    }

    private static bool IsConstantLike(IOperation operation)
    {
        operation = operation.Unwrap();
        if (operation.ConstantValue.HasValue) return true;
        return operation is IDefaultValueOperation or ILiteralOperation
               || operation is IFieldReferenceOperation { Field.Name: "Empty" };
    }

    private static bool IsTextOrBytes(ITypeSymbol? type)
    {
        if (type is null) return false;
        if (type.SpecialType == SpecialType.System_String) return true;
        if (type is IArrayTypeSymbol { ElementType.SpecialType: SpecialType.System_Byte }) return true;
        return type is INamedTypeSymbol { Name: "Span" or "ReadOnlySpan" or "Memory" or "ReadOnlyMemory" } named
               && named.TypeArguments.Length == 1 && named.TypeArguments[0].SpecialType is SpecialType.System_Byte or SpecialType.System_Char;
    }

    private static ImmutableDictionary<string, string?> Properties(string key, string value) =>
        ImmutableDictionary<string, string?>.Empty.Add(key, value);
}
