using System.Text.Json;
using System.Text.Json.Serialization;

namespace SendScore;

/// <summary>The sendscore.verdict/v1 report. Unknown fields are ignored, since the schema may add them.</summary>
public sealed record Verdict
{
    [JsonPropertyName("schema")] public string Schema { get; init; } = "";
    [JsonPropertyName("id")] public string? Id { get; init; }
    [JsonPropertyName("message")] public MessageInfo Message { get; init; } = new();
    [JsonPropertyName("publication")] public string? Publication { get; init; }
    [JsonPropertyName("verdict")] public string Status { get; init; } = "";
    [JsonPropertyName("ready_to_send")] public bool ReadyToSend { get; init; }
    [JsonPropertyName("summary")] public string Summary { get; init; } = "";
    [JsonPropertyName("top_fixes")] public List<TopFix> TopFixes { get; init; } = new();
    [JsonPropertyName("checks")] public List<Check> Checks { get; init; } = new();
    [JsonPropertyName("changes")] public List<Change>? Changes { get; init; }
    [JsonPropertyName("fingerprint")] public Fingerprint? Fingerprint { get; init; }
    [JsonPropertyName("explanation")] public string? Explanation { get; init; }
    [JsonPropertyName("note")] public string Note { get; init; } = "";
}

/// <summary>What was checked.</summary>
public sealed record MessageInfo
{
    [JsonPropertyName("received_at")] public string ReceivedAt { get; init; } = "";
    [JsonPropertyName("from")] public string From { get; init; } = "";
    [JsonPropertyName("subject")] public string Subject { get; init; } = "";
    [JsonPropertyName("message_id")] public string MessageId { get; init; } = "";
    [JsonPropertyName("size_bytes")] public long SizeBytes { get; init; }
}

/// <summary>What to change, and who can change it: "you" or "provider".</summary>
public sealed record Fix
{
    [JsonPropertyName("who")] public string Who { get; init; } = "";
    [JsonPropertyName("text")] public string Text { get; init; } = "";
}

/// <summary>One rule applied to the message, with the evidence it looked at.</summary>
public sealed record Check
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("category")] public string Category { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "";
    [JsonPropertyName("title")] public string Title { get; init; } = "";
    [JsonPropertyName("detail")] public string? Detail { get; init; }
    [JsonPropertyName("evidence")] public Dictionary<string, JsonElement>? Evidence { get; init; }
    [JsonPropertyName("fix")] public Fix? Fix { get; init; }
    [JsonPropertyName("docs")] public string? Docs { get; init; }
    [JsonPropertyName("reason")] public string? Reason { get; init; }
}

/// <summary>One of the fixes to make first.</summary>
public sealed record TopFix
{
    [JsonPropertyName("check")] public string Check { get; init; } = "";
    [JsonPropertyName("who")] public string Who { get; init; } = "";
    [JsonPropertyName("fix")] public string Fix { get; init; } = "";
}

/// <summary>One difference from the previous issue.</summary>
public sealed record Change
{
    [JsonPropertyName("field")] public string Field { get; init; } = "";
    [JsonPropertyName("before")] public JsonElement Before { get; init; }
    [JsonPropertyName("after")] public JsonElement After { get; init; }
    [JsonPropertyName("worsened")] public string? Worsened { get; init; }
}

/// <summary>What the comparison looks at.</summary>
public sealed record Fingerprint
{
    [JsonPropertyName("dkim_domains")] public List<string>? DkimDomains { get; init; }
    [JsonPropertyName("dkim_selectors")] public List<string>? DkimSelectors { get; init; }
    [JsonPropertyName("return_path_domain")] public string ReturnPathDomain { get; init; } = "";
    [JsonPropertyName("remote_ip")] public string? RemoteIp { get; init; }
    [JsonPropertyName("ptr")] public string? Ptr { get; init; }
    [JsonPropertyName("list_unsubscribe")] public bool ListUnsubscribe { get; init; }
    [JsonPropertyName("one_click")] public bool OneClick { get; init; }
    [JsonPropertyName("link_hosts")] public List<string>? LinkHosts { get; init; }
    [JsonPropertyName("html_bytes")] public long HtmlBytes { get; init; }
    [JsonPropertyName("links")] public long Links { get; init; }
    [JsonPropertyName("images")] public long Images { get; init; }
    [JsonPropertyName("auth")] public Dictionary<string, string>? Auth { get; init; }
}

/// <summary>The differences between two saved messages.</summary>
public sealed record DiffResult
{
    [JsonPropertyName("before")] public string Before { get; init; } = "";
    [JsonPropertyName("after")] public string After { get; init; } = "";
    [JsonPropertyName("changes")] public List<Change>? Changes { get; init; }
}
