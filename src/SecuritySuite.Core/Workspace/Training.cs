using System.Text.Json.Serialization;
using SecuritySuite.Shield;

namespace SecuritySuite.Workspace;

/// <summary>
/// Local pass-and-play tabletop question bank. No shared game state, no I/O.
/// </summary>
/// <remarks>
/// <para>
/// Scenarios are generated from the attack-pressure matrix, so each question is
/// a goal-and-entry-point pair with the modelled defence as its correct answer.
/// </para>
/// <para>
/// These are planning exercises, not tests of anything. The disclaimer is
/// returned in the payload rather than left to the UI, because "500 scenarios"
/// in a security tool reads as "500 validated exploit tests" unless something
/// says otherwise.
/// </para>
/// <para>
/// Grading is stateless: the caller owns turns and each player's totals, which
/// is what makes two players on one screen possible without the server holding
/// a session.
/// </para>
/// </remarks>
public sealed class Training
{
    public const string Disclaimer =
        "500 synthetic tabletop scenarios derived from the shield attack-pressure model. " +
        "These are NOT 500 validated exploits or malware tests. " +
        "No payloads are executed and no findings or remediation state are changed.";

    private static readonly string[] ChoiceIds = ["A", "B", "C", "D"];

    /// <summary>
    /// The three wrong answers, which are wrong in three different ways:
    /// skipping investigation, destroying evidence, and reducing visibility.
    /// </summary>
    private static readonly string[] Distractors =
    [
        "Close the alert without checking the evidence or documenting it.",
        "Delete every file on the affected system before reviewing evidence.",
        "Disable monitoring and keep using the suspected entry point.",
    ];

    private readonly Dictionary<string, TrainingScenario> _scenarios = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _answers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _explanations = new(StringComparer.Ordinal);

    public Training(int scenarios = 500)
    {
        // Built from the same matrix the posture panel shows, so a question's
        // correct answer is always the defence the suite actually recommends.
        var rows = ShieldPosture.AttackPressureRows(scenarios);

        for (var index = 0; index < rows.Count; index++)
        {
            var row = rows[index];
            var options = new List<(string Label, bool Correct)>
            {
                (row.Defense, true),
                (Distractors[0], false),
                (Distractors[1], false),
                (Distractors[2], false),
            };

            // Rotate so the correct answer is not always A. A fixed position
            // would let someone score without reading the question.
            var rotation = index % options.Count;
            options = [.. options.Skip(rotation), .. options.Take(rotation)];

            var choices = new List<TrainingChoice>(options.Count);
            for (var i = 0; i < options.Count; i++)
            {
                choices.Add(new TrainingChoice(ChoiceIds[i], options[i].Label));
                if (options[i].Correct) _answers[row.Id] = ChoiceIds[i];
            }

            _scenarios[row.Id] = new TrainingScenario
            {
                Id = row.Id,
                Synthetic = true,
                Goal = row.Goal,
                Entry = row.Entry,
                Severity = row.Severity,
                Question = "Synthetic tabletop: evidence suggests " + row.Goal + " via " +
                           row.Entry + ". Which response best matches the modeled defensive plan?",
                Choices = choices,
            };

            _explanations[row.Id] =
                "For the modeled " + row.Goal + " scenario via " + row.Entry + ": " +
                row.Defense + " Review evidence and scope before acting; a detection alone " +
                "does not prove compromise. The other choices skip investigation, destroy " +
                "evidence, or reduce visibility. This is a synthetic planning exercise, not " +
                "a validated attack test.";
        }
    }

    /// <summary>
    /// The scenario list. Choices carry id and label only, never the answer key.
    /// </summary>
    public TrainingCatalogue List() => new()
    {
        Scenarios = [.. _scenarios.Values],
        Count = _scenarios.Count,
        Synthetic = true,
        Disclaimer = Disclaimer,
        Mode = "pass-and-play",
        Players = 2,
        MaxScore = 1,
    };

    public TrainingGrade Grade(string? id, string? answer)
    {
        if (id is null || !_scenarios.ContainsKey(id))
            return new TrainingGrade { Ok = false, Error = "unknown scenario id" };

        if (answer is null || !ChoiceIds.Contains(answer))
            return new TrainingGrade { Ok = false, Error = "answer must be a choice id: A, B, C, or D" };

        var expected = _answers[id];
        var correct = answer == expected;
        return new TrainingGrade
        {
            Ok = true,
            Id = id,
            Answer = answer,
            Correct = correct,
            CorrectAnswer = expected,
            Score = correct ? 1 : 0,
            MaxScore = 1,
            Explanation = _explanations[id],
            Synthetic = true,
        };
    }
}

public sealed record TrainingChoice(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("label")] string Label);

public sealed class TrainingScenario
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("synthetic")] public bool Synthetic { get; init; }
    [JsonPropertyName("goal")] public string Goal { get; init; } = "";
    [JsonPropertyName("entry")] public string Entry { get; init; } = "";
    [JsonPropertyName("severity")] public string Severity { get; init; } = "";
    [JsonPropertyName("question")] public string Question { get; init; } = "";

    /// <summary>Id and label only. The answer key never leaves the server.</summary>
    [JsonPropertyName("choices")] public List<TrainingChoice> Choices { get; init; } = [];
}

public sealed class TrainingCatalogue
{
    [JsonPropertyName("scenarios")] public List<TrainingScenario> Scenarios { get; init; } = [];
    [JsonPropertyName("count")] public int Count { get; init; }
    [JsonPropertyName("synthetic")] public bool Synthetic { get; init; }
    [JsonPropertyName("disclaimer")] public string Disclaimer { get; init; } = "";
    [JsonPropertyName("mode")] public string Mode { get; init; } = "";
    [JsonPropertyName("players")] public int Players { get; init; }
    [JsonPropertyName("max_score")] public int MaxScore { get; init; }
}

public sealed class TrainingGrade
{
    [JsonPropertyName("ok")] public bool Ok { get; init; }

    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; init; }

    [JsonPropertyName("answer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Answer { get; init; }

    [JsonPropertyName("correct")] public bool Correct { get; init; }

    [JsonPropertyName("correct_answer")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CorrectAnswer { get; init; }

    [JsonPropertyName("score")] public int Score { get; init; }
    [JsonPropertyName("max_score")] public int MaxScore { get; init; }

    [JsonPropertyName("explanation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Explanation { get; init; }

    [JsonPropertyName("synthetic")] public bool Synthetic { get; init; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}
