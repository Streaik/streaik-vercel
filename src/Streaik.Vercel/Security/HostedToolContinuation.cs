using System.Text.Json;
using Streaik.Vercel.Models;

namespace Streaik.Vercel.Security;

/// <summary>Client-carried Vercel tool continuations. Pending decisions can dispatch; history never can.</summary>
public sealed class HostedToolContinuation(ToolApprovalSigner? signer)
{
    public const string ApprovalName = "streaik_hosted_mcp_approval";
    public const string ResultName = "streaik_hosted_mcp_result";
    private const string CallKey = "streaikHostedCall";
    private const string ReceiptKey = "streaikHostedReceipt";
    private const string SignatureKey = "streaikHostedSignature";

    public static bool IsApproval(ToolInvocationPart part) => IsNamed(part, ApprovalName);
    public static bool IsResult(ToolInvocationPart part) => IsNamed(part, ResultName);
    private static bool IsNamed(ToolInvocationPart part, string name) => part.Type == "tool-" + name
        || part.Type == "dynamic-tool" && part.ToolName == name;

    public IReadOnlyList<UIMessagePart> Request<T>(string scope, string name, string server, JsonElement input, T call)
    {
        ValidateInput(input);
        var id = Guid.NewGuid().ToString("N");
        var data = JsonSerializer.SerializeToElement(call, JsonSerializerOptions.Web);
        return [new ToolCallPart { ToolCallId = id, ToolName = ApprovalName, Title = $"Run MCP tool: {name}",
                   Input = input, ProviderExecuted = true, Dynamic = true, ToolMetadata = new() { [CallKey] = data } },
                new ToolApprovalRequestUIPart { ToolCallId = id, ApprovalId = id,
                    Signature = signer?.SignContinuation("decision", scope, id, new { input, data }),
                    Reason = "Approve this MCP tool call before it runs.", ApprovalDescriptor = new { server, name } }];
    }

    public (T Call, JsonElement Input, bool Approved) ReadDecision<T>(Role role, ToolInvocationPart part, string scope)
    {
        if (role != Role.assistant || !IsApproval(part) || part.ProviderExecuted != true || part.State != "approval-responded"
            || part.Approval is not { Approved: { } approved } approval || approval.Id != part.ToolCallId
            || part.ToolCallId is not { Length: > 0 and <= 256 } id || part.Input is not JsonElement input
            || part.ToolMetadata?.GetValueOrDefault(CallKey) is not { ValueKind: JsonValueKind.Object } data || data.GetRawText().Length > 96 * 1024)
            throw Invalid();
        ValidateInput(input);
        signer?.ValidateContinuation(approval.Signature, "decision", scope, id, new { input, data });
        return (Read<T>(data), input, approved);
    }

    public IReadOnlyList<UIMessagePart> Complete<T>(string scope, string id, string name, JsonElement input, T receipt, JsonElement output)
    {
        var callId = $"run_{id}";
        var data = JsonSerializer.SerializeToElement(receipt, JsonSerializerOptions.Web);
        Dictionary<string, JsonElement> metadata = new() { [ReceiptKey] = data };
        if (signer is not null)
            metadata[SignatureKey] = JsonSerializer.SerializeToElement(signer.SignContinuation("history", scope, callId, new { input, data, output }));
        return [new ToolCallPart { ToolCallId = callId, ToolName = ResultName, Title = name, Input = input,
                    ProviderExecuted = true, Dynamic = true, ToolMetadata = metadata },
                new ToolOutputAvailablePart { ToolCallId = callId, ProviderExecuted = true, Dynamic = true, Output = output }];
    }

    public (T Receipt, JsonElement Input, JsonElement Output) ReadResult<T>(Role role, ToolInvocationPart part, string scope)
    {
        if (role != Role.assistant || !IsResult(part) || part.ProviderExecuted != true || part.State != "output-available"
            || part.Approval is not null || part.ToolCallId is not { Length: > 4 and <= 260 } id || !id.StartsWith("run_", StringComparison.Ordinal)
            || part.Input is not JsonElement input || part.Output is not JsonElement output
            || part.ToolMetadata?.GetValueOrDefault(ReceiptKey) is not { ValueKind: JsonValueKind.Object } data
            || data.GetRawText().Length > 96 * 1024 || output.GetRawText().Length > 2 * 1024 * 1024)
            throw Invalid();
        ValidateInput(input);
        var signature = part.ToolMetadata.GetValueOrDefault(SignatureKey);
        signer?.ValidateContinuation(signature.ValueKind == JsonValueKind.String ? signature.GetString() : null,
            "history", scope, id, new { input, data, output });
        return (Read<T>(data), input, output);
    }

    private static T Read<T>(JsonElement data) => data.Deserialize<T>(JsonSerializerOptions.Web) ?? throw Invalid();
    private static void ValidateInput(JsonElement input)
    {
        if (input.ValueKind != JsonValueKind.Object || input.GetRawText().Length > 65536) throw Invalid();
    }
    private static InvalidDataException Invalid() => new("Invalid hosted MCP continuation.");
}
