from collections import defaultdict

class NGramSequenceModel:
    def __init__(self, n=3, min_frequency=2):
        self.n = n
        self.min_frequency = min_frequency
        self.ngram_counts = defaultdict(int)

    def train(self, sequence):
        for i in range(len(sequence) - self.n + 1):
            ngram = tuple(sequence[i:i+self.n])
            self.ngram_counts[ngram] += 1

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