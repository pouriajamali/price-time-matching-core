using System.Globalization;
using System.Text.Json;
using Matching;
using Xunit;

namespace Matching.Tests;
public class MatcherTests
{
    private static IEnumerable<IMatcher> Engines(Limits? limits = null) => new IMatcher[]
    {
        new ScanMatcher(limits),
        new IndexedMatcher(limits)
    };
    private static Command Limit(string id, string side, long price, long qty) => new("limit", id, side, price, qty);
    private static void RejectedWithoutEffects(IMatcher engine, Command c, string reason)
    {
        var before = Contract.StateHash(engine.Snapshot());
        var result = engine.Apply(c);
        Assert.Equal("REJECTED", result.Status);
        Assert.Equal(reason, result.Reason);
        Assert.Empty(result.Trades);
        Assert.Equal(before, Contract.StateHash(engine.Snapshot()));
    }

    [Fact]
    public void PricePriorityPrecedesArrivalAndMakerPriceDeterminesTrade()
    {
        foreach (var e in Engines())
        {
            e.Apply(Limit("old", "sell", 110, 2));
            e.Apply(Limit("better", "sell", 100, 3));
            var r = e.Apply(Limit("buy", "buy", 120, 4));
            Assert.Equal(new[] { "better", "old" }, r.Trades.Select(t => t.MakerId));
            Assert.Equal(new long[] { 100, 110 }, r.Trades.Select(t => t.PriceTicks));
            Assert.Equal(new long[] { 3, 1 }, r.Trades.Select(t => t.Quantity));
            Assert.Equal(new[] { "3:1", "3:2" }, r.Trades.Select(t => t.TradeId));
        }
    }

    [Fact]
    public void SamePriceFifoSurvivesPartialFillAndInterveningRejection()
    {
        foreach (var e in Engines())
        {
            e.Apply(Limit("first", "buy", 100, 3));
            e.Apply(Limit("second", "buy", 100, 4));
            RejectedWithoutEffects(e, Limit("first", "sell", 100, 1), "DUPLICATE_ID");
            Assert.Equal("first", Assert.Single(e.Apply(Limit("a", "sell", 100, 1)).Trades).MakerId);
            var r = e.Apply(Limit("b", "sell", 100, 4));
            Assert.Equal(new[] { "first", "second" }, r.Trades.Select(t => t.MakerId));
            Assert.Equal(new long[] { 2, 2 }, r.Trades.Select(t => t.Quantity));
        }
    }

    [Fact]
    public void ExactTouchCrossesButOneTickGapDoesNot()
    {
        foreach (var e in Engines())
        {
            e.Apply(Limit("a", "buy", 99, 1));
            Assert.Empty(e.Apply(Limit("b", "sell", 100, 1)).Trades);
            Assert.Single(e.Apply(Limit("c", "buy", 100, 1)).Trades);
            Assert.Equal(new[] { "a" }, e.Snapshot().BidPriority);
        }
    }

    [Fact]
    public void CancelOnlyRemainingQuantityAndNeverReusesClosedId()
    {
        foreach (var e in Engines())
        {
            e.Apply(Limit("a", "sell", 100, 5));
            e.Apply(Limit("b", "buy", 100, 2));
            Assert.Equal("ACCEPTED", e.Apply(new("cancel", "a")).Status);
            var a = Assert.Single(e.Snapshot().Orders, o => o.OrderId == "a");
            Assert.Equal((5L, 0L, 2L, 3L), (a.AcceptedQuantity, a.RemainingQuantity, a.ExecutedQuantity, a.CancelledQuantity));
            RejectedWithoutEffects(e, new("cancel", "a"), "NOT_RESTING");
            RejectedWithoutEffects(e, new("cancel", "b"), "NOT_RESTING");
            RejectedWithoutEffects(e, new("cancel", "unknown"), "UNKNOWN_ID");
            RejectedWithoutEffects(e, Limit("a", "buy", 1, 1), "DUPLICATE_ID");
        }
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1000001, 1)]
    [InlineData(1, 0)]
    [InlineData(1, 1000001)]
    [InlineData(long.MaxValue, long.MaxValue)]
    public void InvalidIntegerUnitsRejectBeforeEffects(long price, long quantity)
    {
        foreach (var e in Engines())
            RejectedWithoutEffects(e, Limit("x", "buy", price, quantity), "INVALID_COMMAND");
    }

    [Theory]
    [InlineData("")]
    [InlineData("Capital")]
    [InlineData("x\n")]
    [InlineData("-x")]
    [InlineData("a/b")]
    public void InvalidIdentitiesRejectBeforeEffects(string id)
    {
        foreach (var e in Engines())
            RejectedWithoutEffects(e, Limit(id, "buy", 1, 1), "INVALID_ID");
    }

    [Fact]
    public void CancelExtraFieldsAndUnsupportedOrderTypesReject()
    {
        foreach (var e in Engines())
        {
            RejectedWithoutEffects(e, new("cancel", "a", "buy", 1, 1), "INVALID_COMMAND");
            RejectedWithoutEffects(e, new("market", "a", "buy", 1, 1), "INVALID_COMMAND");
        }
    }

    [Fact]
    public void FullBookAcceptsFullyCrossingOrderAndChecksProspectiveCapacity()
    {
        foreach (var e in Engines(new(2, 10)))
        {
            e.Apply(Limit("s", "sell", 100, 2));
            e.Apply(Limit("b", "buy", 90, 2));
            RejectedWithoutEffects(e, Limit("extra", "buy", 80, 1), "RESTING_CAPACITY");
            Assert.Equal("ACCEPTED", e.Apply(Limit("cross", "buy", 100, 1)).Status);
            Assert.Equal(2, e.Snapshot().Orders.Count(o => o.RemainingQuantity > 0));
            Assert.Equal("ACCEPTED", e.Apply(Limit("replace-space", "buy", 100, 3)).Status);
            Assert.Equal(2, e.Snapshot().Orders.Count(o => o.RemainingQuantity > 0));
        }
    }

    [Fact]
    public void RejectedCapacityDoesNotReserveIdentityOrSequence()
    {
        foreach (var e in Engines(new(1, 3)))
        {
            e.Apply(Limit("old", "buy", 1, 1));
            RejectedWithoutEffects(e, Limit("new", "buy", 1, 1), "RESTING_CAPACITY");
            e.Apply(new("cancel", "old"));
            Assert.Equal(3, e.Apply(Limit("new", "buy", 1, 1)).AcceptedSequence);
        }
    }

    [Fact]
    public void LifetimeRegistryIsBoundedEvenAfterAllOrdersClose()
    {
        foreach (var e in Engines(new(1, 2)))
        {
            e.Apply(Limit("a", "buy", 1, 1));
            e.Apply(new("cancel", "a"));
            e.Apply(Limit("b", "buy", 1, 1));
            e.Apply(new("cancel", "b"));
            RejectedWithoutEffects(e, Limit("c", "buy", 1, 1), "LIFETIME_ID_CAPACITY");
        }
    }

    [Fact]
    public void ExactDefaultRestingBoundaryDoesNotAdmitTenThousandAndOne()
    {
        var e = new IndexedMatcher();
        for (int i = 0; i < 10000; i++)
            Assert.Equal("ACCEPTED", e.Apply(Limit("o" + i, "buy", 1, 1)).Status);
        RejectedWithoutEffects(e, Limit("overflow", "buy", 1, 1), "RESTING_CAPACITY");
        Assert.Equal(10000, e.Snapshot().BidPriority.Count);
    }

    [Fact]
    public void SequenceTerminalStateRejectsFurtherEffects()
    {
        IMatcher[] engines =
        {
            new ScanMatcher(long.MaxValue - 1, 0, 0, 0, 0),
            new IndexedMatcher(long.MaxValue - 1, 0, 0, 0, 0)
        };
        foreach (var e in engines)
        {
            Assert.Equal(long.MaxValue, e.Apply(Limit("a", "buy", 1, 1)).AcceptedSequence);
            RejectedWithoutEffects(e, new("cancel", "a"), "SEQUENCE_EXHAUSTED");
        }
    }

    [Fact]
    public void AcceptedQuantityOverflowRejectsBeforeMutation()
    {
        IMatcher[] engines =
        {
            new ScanMatcher(0, long.MaxValue, 0, 0, 0),
            new IndexedMatcher(0, long.MaxValue, 0, 0, 0)
        };
        foreach (var e in engines)
            RejectedWithoutEffects(e, Limit("a", "buy", 1, 1), "ARITHMETIC_EXHAUSTED");
    }

    [Fact]
    public void ExecutedQuantityOverflowRejectsPlannedCrossBeforeMakerMutation()
    {
        IMatcher[] engines =
        {
            new ScanMatcher(0, 0, long.MaxValue, 0, 0),
            new IndexedMatcher(0, 0, long.MaxValue, 0, 0)
        };
        foreach (var e in engines)
        {
            e.Apply(Limit("a", "sell", 1, 1));
            RejectedWithoutEffects(e, Limit("b", "buy", 1, 1), "ARITHMETIC_EXHAUSTED");
        }
    }

    [Fact]
    public void NotionalOverflowRejectsEntireMultiMakerPlan()
    {
        IMatcher[] engines =
        {
            new ScanMatcher(0, 0, 0, 0, long.MaxValue - 1),
            new IndexedMatcher(0, 0, 0, 0, long.MaxValue - 1)
        };
        foreach (var e in engines)
        {
            e.Apply(Limit("a", "sell", 1, 1));
            e.Apply(Limit("b", "sell", 2, 1));
            RejectedWithoutEffects(e, Limit("c", "buy", 2, 2), "ARITHMETIC_EXHAUSTED");
        }
    }

    [Fact]
    public void CancelQuantityOverflowRejectsWithoutRemovingOrder()
    {
        IMatcher[] engines =
        {
            new ScanMatcher(0, 0, 0, long.MaxValue, 0),
            new IndexedMatcher(0, 0, 0, long.MaxValue, 0)
        };
        foreach (var e in engines)
        {
            e.Apply(Limit("a", "buy", 1, 1));
            RejectedWithoutEffects(e, new("cancel", "a"), "ARITHMETIC_EXHAUSTED");
        }
    }

    [Fact]
    public void EveryAcceptedOrderConservesQuantityAcrossSeededCommands()
    {
        var random = new Random(7021);
        var a = new ScanMatcher(new(64, 2000));
        var b = new IndexedMatcher(new(64, 2000));
        for (int i = 0; i < 1000; i++)
        {
            var c = i % 5 == 0 ? new Command("cancel", "o" + random.Next(i + 1)) : Limit("o" + i, random.Next(2) == 0 ? "buy" : "sell", 95 + random.Next(11), 1 + random.Next(20));
            var x = a.Apply(c);
            var y = b.Apply(c);
            Assert.Equal(JsonSerializer.Serialize(x, Wire.Options), JsonSerializer.Serialize(y, Wire.Options));
            var state = b.Snapshot();
            Assert.Equal(Contract.StateHash(a.Snapshot()), Contract.StateHash(state));
            Assert.All(state.Orders, o => Assert.Equal(o.AcceptedQuantity, o.RemainingQuantity + o.ExecutedQuantity + o.CancelledQuantity));
            Assert.Equal(state.AcceptedQuantity, state.Orders.Sum(o => o.RemainingQuantity) + 2 * state.ExecutedQuantity + state.CancelledQuantity);
        }
    }

    [Fact]
    public void SnapshotDoesNotExposeMutableInternalState()
    {
        foreach (var e in Engines())
        {
            e.Apply(Limit("a", "buy", 1, 1));
            var copy = e.Snapshot();
            ((OrderView[])copy.Orders)[0] = copy.Orders[0] with
            {
                RemainingQuantity = 999
            };
            Assert.Equal(1, e.Snapshot().Orders[0].RemainingQuantity);
        }
    }

    [Fact]
    public void CanonicalHashIsCultureIndependent()
    {
        var e = new IndexedMatcher();
        e.Apply(Limit("a", "buy", 1, 1));
        var expected = Contract.StateHash(e.Snapshot());
        var old = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fa-IR");
            Assert.Equal(expected, Contract.StateHash(e.Snapshot()));
        }
        finally
        {
            CultureInfo.CurrentCulture = old;
        }
    }

    [Fact]
    public void StrictWireRejectsDuplicateUnknownAndMissingFields()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Command>("{\"kind\":\"cancel\",\"orderId\":\"a\",\"orderId\":\"b\"}", Wire.Options));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Command>("{\"kind\":\"cancel\",\"orderId\":\"a\",\"owner\":\"x\"}", Wire.Options));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Command>("{}", Wire.Options));
    }

    [Fact]
    public void NumericStringsAndFractionalUnitsDoNotCoerceToIntegerDomain()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Command>("{\"kind\":\"limit\",\"orderId\":\"a\",\"side\":\"buy\",\"priceTicks\":\"1\",\"quantity\":1}", Wire.Options));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<Command>("{\"kind\":\"limit\",\"orderId\":\"a\",\"side\":\"buy\",\"priceTicks\":1.5,\"quantity\":1}", Wire.Options));
    }
}
