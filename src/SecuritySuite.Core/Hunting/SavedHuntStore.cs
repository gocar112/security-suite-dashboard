using System.Text.Json;
using System.Text.Json.Serialization;
using SecuritySuite.Storage;

namespace SecuritySuite.Hunting;

/// <summary>
/// Named hunt queries, kept beside the other sidecars.
/// </summary>
/// <remarks>
/// A hunt worth running once is usually worth running again, and retyping a
/// query from memory is how an analyst ends up running a subtly different one.
/// Queries are validated before they are saved, so a stored hunt cannot fail to
/// parse later and the operator finds out at save time rather than mid-incident.
/// </remarks>
public sealed class SavedHuntStore
{
    private const int MaxHunts = 200;
    private const int MaxName = 80;
    private const int MaxQuery = 2000;

    private readonly Lock _gate = new();
    private readonly Dictionary<string, SavedHunt> _hunts = new(StringComparer.Ordinal);
    private readonly Action<string> _warn;

    public string Path { get; }

    public SavedHuntStore(string path, Action<string>? warn = null)
    {
        Path = System.IO.Path.GetFullPath(path);
        _warn = warn ?? (_ => { });
        Load();
    }

    private void Load()
    {
        if (!File.Exists(Path)) return;
        try
        {
            var raw = JsonSerializer.Deserialize<Dictionary<string, SavedHunt>>(
                File.ReadAllText(Path), SuiteJson.Options);
            if (raw is null) return;

            foreach (var (key, value) in raw)
            {
                if (value is not null) _hunts[key] = value;
            }
        }
        catch (Exception exc) when (exc is JsonException or IOException or UnauthorizedAccessException)
        {
            _warn("[!] Ignoring unreadable saved hunts: " + exc.Message);
        }
    }

    private void Persist()
    {
        try
        {
            var parent = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

            var staging = Path + ".tmp";
            File.WriteAllText(staging, JsonSerializer.Serialize(_hunts, SuiteJson.Pretty));
            File.Move(staging, Path, overwrite: true);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException)
        {
            _warn("[-] Could not persist saved hunts: " + exc.Message);
        }
    }

    public List<SavedHunt> All()
    {
        lock (_gate)
        {
            return [.. _hunts.Values
                .OrderBy(h => h.Name, StringComparer.OrdinalIgnoreCase)
                .Select(h => h.Copy())];
        }
    }

    /// <summary>
    /// Save a named query, replacing one of the same name.
    /// </summary>
    /// <remarks>
    /// The query is parsed first. Storing one that does not parse would move the
    /// failure from the moment it is written to the moment it is needed.
    /// </remarks>
    public SavedHunt Save(string? name, string? query, string? description = "")
    {
        var cleanName = Clip(name, MaxName);
        if (cleanName.Length == 0) throw new ArgumentException("name is required");

        var cleanQuery = Clip(query, MaxQuery);
        if (cleanQuery.Length == 0) throw new ArgumentException("query is required");

        HuntQuery.Parse(cleanQuery);   // throws HuntQueryException on a bad query

        var record = new SavedHunt
        {
            Id = EventStore.NewId(),
            Name = cleanName,
            Query = cleanQuery,
            Description = Clip(description, 400),
            SavedAt = EventStore.NowIso(),
        };

        lock (_gate)
        {
            // Name is the identity an operator uses, so saving the same name
            // twice updates rather than accumulating near-duplicates.
            var existing = _hunts.Values.FirstOrDefault(
                h => string.Equals(h.Name, cleanName, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                record.Id = existing.Id;
                _hunts.Remove(existing.Id);
            }

            if (_hunts.Count >= MaxHunts)
                throw new ArgumentException("at most " + MaxHunts + " saved hunts");

            _hunts[record.Id] = record;
            Persist();
        }
        return record.Copy();
    }

    public bool Delete(string huntId)
    {
        lock (_gate)
        {
            if (!_hunts.Remove(huntId)) return false;
            Persist();
            return true;
        }
    }

    private static string Clip(string? value, int length)
    {
        var trimmed = (value ?? "").Trim();
        return trimmed.Length > length ? trimmed[..length] : trimmed;
    }
}

public sealed class SavedHunt
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("query")] public string Query { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";
    [JsonPropertyName("saved_at")] public string SavedAt { get; set; } = "";

    public SavedHunt Copy() => new()
    {
        Id = Id,
        Name = Name,
        Query = Query,
        Description = Description,
        SavedAt = SavedAt,
    };
}
