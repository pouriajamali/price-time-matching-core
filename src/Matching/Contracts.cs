using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Matching;
public sealed record Command(string Kind, string OrderId, string? Side = null, long? PriceTicks = null, long? Quantity = null);
public sealed record Trade(string TradeId, string MakerId, string TakerId, long PriceTicks, long Quantity);
public sealed record Result(string Status, string Reason, long AcceptedSequence, IReadOnlyList<Trade> Trades);
public sealed record OrderView(string OrderId, string Side, long PriceTicks, long AcceptedSequence, long AcceptedQuantity, long RemainingQuantity, long ExecutedQuantity, long CancelledQuantity);
public sealed record Snapshot(long AcceptedSequence, long AcceptedQuantity, long ExecutedQuantity, long CancelledQuantity, long ExecutedNotional, IReadOnlyList<OrderView> Orders, IReadOnlyList<string> BidPriority, IReadOnlyList<string> AskPriority);
public sealed record Limits(int Resting = 10000, int LifetimeIds = 100000)
{
    public void Validate()
    {
        if (Resting is < 1 or > 10000 || LifetimeIds < Resting || LifetimeIds > 100000)
            throw new ArgumentException("Invalid bounded limits");
    }
}

public interface IMatcher
{
    Result Apply(Command command);
    Snapshot Snapshot();
}

public static class Wire
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
        NumberHandling = JsonNumberHandling.Strict,
        MaxDepth = 8
    };
}

public static class Contract
{
    public static string? Invalid(Command c)
    {
        if (c is null || c.OrderId is null || c.OrderId.Length is < 1 or > 32 || !c.OrderId.All(ch => ch is >= 'a' and <= 'z' or >= '0' and <= '9' or '-') || c.OrderId[0] == '-')
            return "INVALID_ID";
        return c.Kind switch
        {
            "limit" when c.Side is "buy" or "sell" && c.PriceTicks is >= 1 and <= 1000000 && c.Quantity is >= 1 and <= 1000000 => null,
            "cancel" when c.Side is null && c.PriceTicks is null && c.Quantity is null => null,
            _ => "INVALID_COMMAND"
        };
    }

    public static bool Crosses(Command c, long restingPrice) => c.Side == "buy" ? restingPrice <= c.PriceTicks : restingPrice >= c.PriceTicks;
    public static Snapshot Describe(long seq, long accepted, long executed, long cancelled, long notional, IEnumerable<OrderView> orders)
    {
        var all = orders.OrderBy(o => o.OrderId, StringComparer.Ordinal).ToArray();
        var bids = all.Where(o => o.Side == "buy" && o.RemainingQuantity > 0).OrderByDescending(o => o.PriceTicks).ThenBy(o => o.AcceptedSequence).Select(o => o.OrderId).ToArray();
        var asks = all.Where(o => o.Side == "sell" && o.RemainingQuantity > 0).OrderBy(o => o.PriceTicks).ThenBy(o => o.AcceptedSequence).Select(o => o.OrderId).ToArray();
        return new(seq, accepted, executed, cancelled, notional, all, bids, asks);
    }

    public static string StateHash(Snapshot state)
    {
        var text = new StringBuilder();
        void Line(long value) => text.Append(value.ToString(CultureInfo.InvariantCulture)).Append('\n');
        Line(state.AcceptedSequence);
        Line(state.AcceptedQuantity);
        Line(state.ExecutedQuantity);
        Line(state.CancelledQuantity);
        Line(state.ExecutedNotional);
        foreach (var o in state.Orders)
            text.AppendJoin('|', o.OrderId, o.Side, o.PriceTicks.ToString(CultureInfo.InvariantCulture), o.AcceptedSequence.ToString(CultureInfo.InvariantCulture), o.AcceptedQuantity.ToString(CultureInfo.InvariantCulture), o.RemainingQuantity.ToString(CultureInfo.InvariantCulture), o.ExecutedQuantity.ToString(CultureInfo.InvariantCulture), o.CancelledQuantity.ToString(CultureInfo.InvariantCulture)).Append('\n');
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(text.ToString())));
    }
}
