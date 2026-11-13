using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Schlosser;

/// <summary>
/// Several rules depend on what a variable is called (a "resetToken" needs a real random generator, a "pageToken" label does not).
/// Names are split into words and the last word decides: TokenType, PasswordHeader and SecretName are not secrets.
/// </summary>
internal static class Names
{
    private static readonly HashSet<string> KeyQualifiers = new(StringComparer.Ordinal)
    {
        "api", "secret", "private", "signing", "encryption", "jwt", "access", "master", "auth", "hmac", "shared", "symmetric", "subscription",
    };

    /// <summary>"resetTokenId" → reset, token, id. Handles camelCase, PascalCase, snake_case and acronyms (APIKey → api, key).</summary>
    public static List<string> Words(string name)
    {
        var words = new List<string>();
        var start = 0;
        for (var i = 1; i <= name.Length; i++)
        {
            var boundary = i == name.Length;
            if (!boundary)
            {
                var previous = name[i - 1];
                var current = name[i];
                if (current == '_' || previous == '_') boundary = true;
                else if (char.IsUpper(current) && !char.IsUpper(previous)) boundary = true;
                else if (char.IsUpper(current) && i + 1 < name.Length && char.IsLower(name[i + 1])) boundary = true; // APIKey → API | Key
                else if (char.IsDigit(current) != char.IsDigit(previous)) boundary = true;
            }

            if (!boundary) continue;
            var word = name.Substring(start, i - start).Trim('_');
            if (word.Length > 0 && !char.IsDigit(word[0])) words.Add(word.ToLowerInvariant());
            start = i;
        }

        return words;
    }

    /// <summary>A name for something that must stay secret: password, clientSecret, apiKey, accessToken ...</summary>
    public static bool IsSecret(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var words = Words(name!);
        if (words.Count == 0) return false;
        var last = words[words.Count - 1];
        var previous = words.Count > 1 ? words[words.Count - 2] : "";

        switch (last)
        {
            case "password":
            case "passwort":
            case "kennwort":
            case "passwd":
            case "pwd":
            case "passphrase":
            case "secret":
            case "apikey":
                return true;
            case "token":
                // a CancellationToken is not a secret, and neither are paging or continuation tokens
                return previous is not ("cancellation" or "continuation" or "page" or "paging" or "next" or "sync");
            case "key":
                return KeyQualifiers.Contains(previous);
            default:
                return false;
        }
    }

    /// <summary>A name for a value where a timing difference in a comparison leaks information.</summary>
    public static bool IsComparedSecret(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (IsSecret(name)) return true;
        var words = Words(name!);
        if (words.Count == 0) return false;
        var previous = words.Count > 1 ? words[words.Count - 2] : "";
        switch (words[words.Count - 1])
        {
            case "signature":
            case "hmac":
            case "mac":
            case "otp":
            case "totp":
                return true;
            case "hash":
            case "digest":
                // A password or token hash is a secret. The hash of a file or of an audit record is public:
                // comparing those is an integrity check, where timing tells an attacker nothing.
                return previous is "password" or "passwort" or "kennwort" or "token" or "secret" or "key" or "code" or "pin";
            default:
                return false;
        }
    }

    /// <summary>A name for a value that must not be written to a log.</summary>
    public static bool IsLoggedSecret(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (IsSecret(name)) return true;
        var words = Words(name!);
        if (words.Count == 0) return false;
        var last = words[words.Count - 1];
        var previous = words.Count > 1 ? words[words.Count - 2] : "";
        return last is "cvv" or "cvc" or "authorization" or "iban"
               || (last == "number" && previous is "card")
               || (last == "string" && previous is "connection");
    }

    /// <summary>What should be random: the name of the variable, method or type that receives the value.</summary>
    public static bool NeedsCryptoRandom(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        foreach (var word in Words(name!))
        {
            switch (word)
            {
                case "token":
                case "password":
                case "passwort":
                case "secret":
                case "salt":
                case "nonce":
                case "otp":
                case "totp":
                case "pin":
                case "key":
                case "apikey":
                case "iv":
                case "session":
                case "csrf":
                case "captcha":
                case "verification":
                case "reset":
                case "invite":
                case "invitation":
                case "voucher":
                case "coupon":
                case "code":
                case "credential":
                case "credentials":
                    return true;
            }
        }

        return false;
    }

    /// <summary>The name of the last identifier in an expression: user.PasswordHash → PasswordHash, Convert.ToBase64String(mac) → mac.</summary>
    public static string? Of(IOperation? operation)
    {
        operation = operation?.Unwrap();
        switch (operation)
        {
            case null: return null;
            case ILocalReferenceOperation local: return local.Local.Name;
            case IParameterReferenceOperation parameter: return parameter.Parameter.Name;
            case IMemberReferenceOperation member: return member.Member.Name;
            case IInvocationOperation invocation:
                // wrappers keep the meaning of what they wrap
                if (invocation.Arguments.Length == 1 && invocation.TargetMethod.Name is "ToBase64String" or "ToHexString" or "GetString" or "GetBytes" or "FromBase64String" or "FromHexString")
                    return Of(invocation.Arguments[0].Value);
                if (invocation.Instance is not null && invocation.TargetMethod.Name is "ToString" or "Trim" or "ToLowerInvariant" or "ToUpperInvariant" or "AsSpan" or "ToArray")
                    return Of(invocation.Instance);
                return null;
            case IArrayElementReferenceOperation element: return Of(element.ArrayReference);
            default: return null;
        }
    }

    /// <summary>The name that receives the value of this expression: the variable, field, property or parameter it is stored in or passed to.</summary>
    public static string? Receiver(IOperation operation)
    {
        for (var current = operation; current.Parent is { } parent; current = parent)
        {
            switch (parent)
            {
                case IConversionOperation:
                case IParenthesizedOperation:
                case ICoalesceOperation:
                case IConditionalOperation conditional when !ReferenceEquals(conditional.Condition, current):
                case IAwaitOperation:
                case IBinaryOperation:
                case IInterpolationOperation:
                case IInterpolatedStringOperation:
                case IArrayElementReferenceOperation:
                case IInvocationOperation call when ReferenceEquals(call.Instance, current): // random.Next(999999).ToString("000000")
                case IPropertyReferenceOperation { Arguments.Length: > 0 }:                   // alphabet[random.Next(n)]
                case IArgumentOperation { Parent: IPropertyReferenceOperation }:
                    continue;
                case IVariableInitializerOperation { Parent: IVariableDeclaratorOperation declarator }:
                    return declarator.Symbol.Name;
                case IVariableInitializerOperation { Parent: IVariableDeclarationOperation { Declarators.Length: 1 } declaration }:
                    return declaration.Declarators[0].Symbol.Name;
                case IFieldInitializerOperation { InitializedFields.Length: > 0 } field:
                    return field.InitializedFields[0].Name;
                case IPropertyInitializerOperation { InitializedProperties.Length: > 0 } property:
                    return property.InitializedProperties[0].Name;
                case IAssignmentOperation assignment when ReferenceEquals(assignment.Value, current):
                    return Of(assignment.Target);
                case IArgumentOperation argument:
                    return argument.Parameter?.Name;
                case IReturnOperation:
                    return null;
                default:
                    return null;
            }
        }

        return null;
    }

    /// <summary>The method (not lambda or local function) and type this operation is written in.</summary>
    public static (string? Method, string? Type) Enclosing(IOperation operation, ISymbol containingSymbol)
    {
        var symbol = containingSymbol;
        while (symbol is IMethodSymbol { MethodKind: MethodKind.AnonymousFunction or MethodKind.LocalFunction })
            symbol = symbol.ContainingSymbol;
        return (symbol is IMethodSymbol or IPropertySymbol or IFieldSymbol ? symbol.Name : null, symbol?.ContainingType?.Name);
    }
}
