namespace SmartSecureArchiver.Core.Optimization;

/// <summary>
/// Запис метрик одного покоління Генетичного алгоритму (Issue #36).
/// </summary>
public sealed record GaGenerationRecord(
    int Generation,
    double BestQ,
    double AverageQ,
    double WorstQ,
    double BestS,
    double BestT,
    GeneticParameters BestParameters,
    int EvaluationsSoFar
);

/// <summary>
/// Повний журнал еволюції ГА для збереження у репозиторій та формування Таблиці №5 звіту.
/// </summary>
public sealed record GaOptimizationReport(
    int Seed,
    int PopulationSize,
    int Generations,
    int TotalEvaluations,
    double BestInitialQ,
    double BestFinalQ,
    GeneticParameters BestParameters,
    IReadOnlyList<GaGenerationRecord> GenerationsHistory,
    double ElapsedSeconds
);

/// <summary>
/// Результат одного прогону Random Search із тим самим бюджетом обчислень Q (Issue #36).
/// </summary>
public sealed record RandomSearchRecord(
    int Iteration,
    double CandidateQ,
    double BestQSoFar,
    GeneticParameters CandidateParameters
);

/// <summary>
/// Повний звіт Random Search baseline для порівняння з ГА (Таблиця №5 звіту).
/// </summary>
public sealed record RandomSearchReport(
    int Seed,
    int Iterations,
    double BestQ,
    double AverageQ,
    double BestS,
    double BestT,
    GeneticParameters BestParameters,
    IReadOnlyList<RandomSearchRecord> History,
    double ElapsedSeconds
);
