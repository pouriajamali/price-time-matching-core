namespace Matching;
/// <summary>Single caller only. Plan all domain/arithmetic/capacity effects before mutating indexed levels.</summary>
public sealed class IndexedMatcher : IMatcher
{
    private sealed class Order(string id, string side, long price, long sequence, long quantity)
    {
        public readonly string Id = id, Side = side;
        public readonly long Price = price, Sequence = sequence, Quantity = quantity;
        public long Remaining = quantity, Executed, Cancelled;
        public LinkedListNode<Order>? Node;
        public OrderView View() => new(Id, Side, Price, Sequence, Quantity, Remaining, Executed, Cancelled);
    }

    private readonly Dictionary<string, Order> orders = new(StringComparer.Ordinal);
    private readonly SortedDictionary<long, LinkedList<Order>> bids = new(Comparer<long>.Create((a, b) => b.CompareTo(a))), asks = [];
    private readonly Limits limits;
    private int resting;
    private long sequence, accepted, executed, cancelled, notional;
    public IndexedMatcher(Limits? limits = null)
    {
        this.limits = limits ?? new();
        this.limits.Validate();
    }

    // Exhaustion seam only in friend tests, never exposed through CLI/import/recovery.
    internal IndexedMatcher(long sequence, long accepted, long executed, long cancelled, long notional) : this()
    {
        this.sequence = sequence;
        this.accepted = accepted;
        this.executed = executed;
        this.cancelled = cancelled;
        this.notional = notional;
    }

    private Result Reject(string reason) => new("REJECTED", reason, sequence, Array.Empty<Trade>());
    public Result Apply(Command command)
    {
        var invalid = Contract.Invalid(command);
        if (invalid is not null)
            return Reject(invalid);
        if (sequence == long.MaxValue)
            return Reject("SEQUENCE_EXHAUSTED");
        if (command.Kind == "cancel")
            return Cancel(command.OrderId);
        if (orders.ContainsKey(command.OrderId))
            return Reject("DUPLICATE_ID");
        if (orders.Count == limits.LifetimeIds)
            return Reject("LIFETIME_ID_CAPACITY");
        var plan = new List<(Order Maker, long Quantity)>();
        var remaining = command.Quantity!.Value;
        var opposite = command.Side == "buy" ? asks : bids;
        int closed = 0;
        long nextAccepted, nextExecuted = executed, nextNotional = notional;
        try
        {
            nextAccepted = checked(accepted + remaining);
            foreach (var level in opposite)
            {
                if (!Contract.Crosses(command, level.Key))
                    break;
                foreach (var maker in level.Value)
                {
                    var quantity = Math.Min(remaining, maker.Remaining);
                    plan.Add((maker, quantity));
                    remaining -= quantity;
                    nextExecuted = checked(nextExecuted + quantity);
                    nextNotional = checked(nextNotional + checked(quantity * maker.Price));
                    if (quantity == maker.Remaining)
                        closed++;
                    if (remaining == 0)
                        break;
                }

                if (remaining == 0)
                    break;
            }
        }
        catch (OverflowException)
        {
            return Reject("ARITHMETIC_EXHAUSTED");
        }

        if (resting - closed + (remaining > 0 ? 1 : 0) > limits.Resting)
            return Reject("RESTING_CAPACITY");
        var nextSequence = sequence + 1;
        var taker = new Order(command.OrderId, command.Side!, command.PriceTicks!.Value, nextSequence, command.Quantity.Value);
        var trades = new List<Trade>(plan.Count);
        foreach (var(maker, quantity)in plan)
        {
            maker.Remaining -= quantity;
            maker.Executed += quantity;
            taker.Remaining -= quantity;
            taker.Executed += quantity;
            trades.Add(new(nextSequence.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + (trades.Count + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), maker.Id, taker.Id, maker.Price, quantity));
            if (maker.Remaining == 0)
                Remove(maker);
        }

        orders.Add(taker.Id, taker);
        if (taker.Remaining > 0)
        {
            var own = taker.Side == "buy" ? bids : asks;
            if (!own.TryGetValue(taker.Price, out var queue))
            {
                queue = [];
                own.Add(taker.Price, queue);
            }

            taker.Node = queue.AddLast(taker);
            resting++;
        }

        sequence = nextSequence;
        accepted = nextAccepted;
        executed = nextExecuted;
        notional = nextNotional;
        return new("ACCEPTED", "LIMIT", sequence, trades);
    }

    private Result Cancel(string id)
    {
        if (!orders.TryGetValue(id, out var order))
            return Reject("UNKNOWN_ID");
        if (order.Remaining == 0)
            return Reject("NOT_RESTING");
        long nextCancelled;
        try
        {
            nextCancelled = checked(cancelled + order.Remaining);
        }
        catch (OverflowException)
        {
            return Reject("ARITHMETIC_EXHAUSTED");
        }

        order.Cancelled += order.Remaining;
        order.Remaining = 0;
        Remove(order);
        cancelled = nextCancelled;
        sequence++;
        return new("ACCEPTED", "CANCEL", sequence, Array.Empty<Trade>());
    }

    private void Remove(Order order)
    {
        var own = order.Side == "buy" ? bids : asks;
        var queue = own[order.Price];
        queue.Remove(order.Node!);
        order.Node = null;
        resting--;
        if (queue.Count == 0)
            own.Remove(order.Price);
    }

    public Snapshot Snapshot() => Contract.Describe(sequence, accepted, executed, cancelled, notional, orders.Values.Select(o => o.View()));
}
