namespace SmartSecureArchiver.Core.Optimization;

public interface IGeneticOptimizer
{
    /// <summary>
    /// Знаходить субоптимальну комбінацію параметрів архіватора на навчальному корпусі,
    /// максимізуючи підсумкову метрику якості Q = αS + βT за допомогою елітизму.
    /// </summary>
    GeneticParameters Optimize(IReadOnlyList<string> sampleFiles, int generations, int populationSize);

    /// <summary>
    /// Випадковий пошук (Random Search) із тим самим бюджетом викликів для обов'язкового baseline-порівняння.
    /// </summary>
    GeneticParameters RunRandomSearch(IReadOnlyList<string> sampleFiles, int iterations);
}
