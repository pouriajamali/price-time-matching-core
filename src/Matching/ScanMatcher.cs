namespace Matching;
/// <summary>Deliberately simple baseline: copy the full ledger, scan/sort resting candidates, atomically replace on acceptance.</summary>
public sealed class ScanMatcher : IMatcher
{
    private List<OrderView> ledger = [];
    private readonly Limits limits;
    private long sequence, accepted, executed, cancelled, notional;
    public ScanMatcher(Limits? limits = null)
    {
        this.limits = limits ?? new();
        this.limits.Validate();
    }

    internal ScanMatcher(long sequence, long accepted, long executed, long cancelled, long notional) : this()
    {
        this.sequence = sequence;
        this.accepted = accepted;
        this.executed = executed;
        this.cancelled = cancelled;
        this.notional = notional;
    }

    public Result Apply(Command c)
    {
        Result Reject(string reason) => new("REJECTED", reason, sequence, Array.Empty<Trade>());
        var invalid = Contract.Invalid(c);
        if (invalid is not null)
            return Reject(invalid);
        if (sequence == long.MaxValue)
            return Reject("SEQUENCE_EXHAUSTED");
        var copy = ledger.ToList();
        var trades = new List<Trade>();
        var nextAccepted = accepted;
        var nextExecuted = executed;
        var nextCancelled = cancelled;
        var nextNotional = notional;
        var nextSequence = sequence + 1;
        try
        {
            if (c.Kind == "cancel")
            {
                int index = copy.FindIndex(o => o.OrderId == c.OrderId);
                if (index < 0)
                    return Reject("UNKNOWN_ID");
                var old = copy[index];
                if (old.RemainingQuantity == 0)
                    return Reject("NOT_RESTING");
                nextCancelled = checked(cancelled + old.RemainingQuantity);
                copy[index] = old with
                {
                    CancelledQuantity = old.CancelledQuantity + old.RemainingQuantity,
                    RemainingQuantity = 0
                };
            }
            else
            {
                if (copy.Any(o => o.OrderId == c.OrderId))
                    return Reject("DUPLICATE_ID");
                if (copy.Count == limits.LifetimeIds)
                    return Reject("LIFETIME_ID_CAPACITY");
                var quantity = c.Quantity!.Value;
                nextAccepted = checked(accepted + quantity);
                var remaining = quantity;
                var candidates = copy.Select((o, i) => (Order: o, Index: i)).Where(x => x.Order.RemainingQuantity > 0 && x.Order.Side != c.Side && (c.Side == "buy" ? x.Order.PriceTicks <= c.PriceTicks : x.Order.PriceTicks >= c.PriceTicks));
                var sorted = c.Side == "buy" ? candidates.OrderBy(x => x.Order.PriceTicks).ThenBy(x => x.Order.AcceptedSequence) : candidates.OrderByDescending(x => x.Order.PriceTicks).ThenBy(x => x.Order.AcceptedSequence);
                foreach (var item in sorted)
                {
                    if (remaining == 0)
                        break;
                    var amount = Math.Min(item.Order.RemainingQuantity, remaining);
                    remaining -= amount;
                    var maker = item.Order;
                    nextExecuted = checked(nextExecuted + amount);
                    nextNotional = checked(nextNotional + checked(amount * maker.PriceTicks));
                    copy[item.Index] = maker with
                    {
                        RemainingQuantity = maker.RemainingQuantity - amount,
                        ExecutedQuantity = maker.ExecutedQuantity + amount
                    };
                    trades.Add(new(nextSequence.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + (trades.Count + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), maker.OrderId, c.OrderId, maker.PriceTicks, amount));
                }

                copy.Add(new(c.OrderId, c.Side!, c.PriceTicks!.Value, nextSequence, quantity, remaining, quantity - remaining, 0));
                if (copy.Count(o => o.RemainingQuantity > 0) > limits.Resting)
                    return Reject("RESTING_CAPACITY");
            }
        }
        catch (OverflowException)
        {
            return Reject("ARITHMETIC_EXHAUSTED");
        }

        ledger = copy;
        sequence = nextSequence;
        accepted = nextAccepted;
        executed = nextExecuted;
        cancelled = nextCancelled;
        notional = nextNotional;
        return new("ACCEPTED", c.Kind == "limit" ? "LIMIT" : "CANCEL", sequence, trades);
    }

    public Snapshot Snapshot() => Contract.Describe(sequence, accepted, executed, cancelled, notional, ledger);
}
