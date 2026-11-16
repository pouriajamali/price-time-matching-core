using System.Text.Json;
using Matching;
using Xunit;

namespace Matching.Tests;

// Expectations are literal fixture data, not values obtained from either engine.
public sealed class CapacityModelTests
{
    private sealed record FixtureDocument(string Schema, string Authorship, Trace[] Traces);
    private sealed record Trace(string Id, int Resting, int LifetimeIds, Step[] Steps);
    private sealed record Step(Command Command, Result Result, Snapshot Snapshot);
    private sealed record Observation(Result Result, Snapshot Snapshot);

    private static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Wire.Options);
    private static IMatcher Engine(bool indexed, Trace trace) => indexed
        ? new IndexedMatcher(new(trace.Resting, trace.LifetimeIds))
        : new ScanMatcher(new(trace.Resting, trace.LifetimeIds));

    [Fact]
    public void FiniteCapacityGoldensReplayAndRejectErasurePreserveFullState()
    {
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "capacity-model-v1.json");
        var raw = File.ReadAllBytes(fixturePath);
        Assert.InRange(raw.Length, 1, 256 * 1024);
        var fixture = JsonSerializer.Deserialize<FixtureDocument>(raw, Wire.Options)!;
        Assert.Equal("matching-capacity-goldens/v1", fixture.Schema);
        var expectedIds = new[] { "A", "B", "C", "D", "E", "F" }
            .SelectMany(id => new[] { id + "-direct", id + "-mirror" }).ToArray();
        Assert.Equal(expectedIds, fixture.Traces.Select(trace => trace.Id));
        Assert.Equal(12, fixture.Traces.Length);
        var commands = fixture.Traces.Sum(trace => trace.Steps.Length);
        Assert.InRange(commands, 1, 192);
        var acceptedCommands = 0;
        var applications = 0;
        foreach (var trace in fixture.Traces)
        {
            Assert.InRange(trace.Steps.Length, 1, 16);
            Assert.Contains((trace.Resting, trace.LifetimeIds), new[] { (1, 8), (2, 8), (1, 2) });
            acceptedCommands += trace.Steps.Count(step => step.Result.Status == "ACCEPTED");
            foreach (var indexed in new[] { false, true })
            {
                var engine = Engine(indexed, trace);
                var replay = Engine(indexed, trace);
                var erased = Engine(indexed, trace);
                foreach (var step in trace.Steps)
                {
                    var before = Bytes(engine.Snapshot());
                    var result = engine.Apply(step.Command);
                    applications++;
                    var state = engine.Snapshot();
                    Assert.Equal(Bytes(step.Result), Bytes(result));
                    Assert.Equal(Bytes(step.Snapshot), Bytes(state));
                    Assert.Equal(result.AcceptedSequence, state.AcceptedSequence);
                    Assert.All(state.Orders, order => Assert.Equal(order.AcceptedQuantity,
                        order.RemainingQuantity + order.ExecutedQuantity + order.CancelledQuantity));
                    Assert.Equal(state.AcceptedQuantity, state.Orders.Sum(order => order.RemainingQuantity)
                        + 2 * state.ExecutedQuantity + state.CancelledQuantity);
                    var actual = new Observation(result, state);
                    var repeated = new Observation(replay.Apply(step.Command), replay.Snapshot());
                    applications++;
                    Assert.Equal(Bytes(actual), Bytes(repeated));
                    if (step.Result.Status == "REJECTED")
                    {
                        Assert.Empty(result.Trades);
                        Assert.Equal(before, Bytes(state));
                    }
                    else
                    {
                        var withoutRejection = new Observation(erased.Apply(step.Command), erased.Snapshot());
                        applications++;
                        Assert.Equal(Bytes(actual), Bytes(withoutRejection));
                    }
                }
                Assert.Equal(Bytes(engine.Snapshot()), Bytes(erased.Snapshot()));
            }
        }
        Assert.Equal(4 * commands + 2 * acceptedCommands, applications);
        Assert.InRange(applications, 1, 1152);
        // The optional receipt contains actual execution counts, never source-stage assertions of a pass.
        var evidence = Environment.GetEnvironmentVariable("MATCHING_CAPACITY_EVIDENCE");
        if (evidence is not null)
        {
            using var file = new FileStream(evidence, FileMode.CreateNew, FileAccess.Write);
            JsonSerializer.Serialize(file, new
            {
                schema = "matching-capacity-csharp/v1", status = "PASS",
                traces = fixture.Traces.Length, baseCommands = commands, acceptedCommands,
                applications, fixtureSha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(raw)),
                scope = "Full golden states, scan/index, repeated replay and rejection-erased accepted projection only"
            }, Wire.Options);
        }
    }
}
