from collections import defaultdict

class NGramSequenceModel:
    def __init__(self, n=3, min_frequency=2):
        # n: sequence length, n = 3 by default; min_frequency: expected occurrence threshold
        self.n = n
        self.min_frequency = min_frequency
        self.ngram_counts = defaultdict(int)

    def train(self, sequence):
        # Learning normal sequence behavior from template IDs
        for i in range(len(sequence) - self.n + 1):
            ngram = tuple(sequence[i:i+self.n])
            self.ngram_counts[ngram] += 1

    # Reporting rare event sequences considered anomalous
    def detect(self, sequence):
        context_anomalies = []
        for i in range(len(sequence) - self.n + 1):
            ngram = tuple(sequence[i:i + self.n])
            if self.ngram_counts.get(ngram, 0) < self.min_frequency:
                context_anomalies.append({
                    "ngram": ngram,
                    "position": i,
                    "severity": "low"
                })
        return context_anomalies