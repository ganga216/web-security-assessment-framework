# modules/risk_engine.py

def calculate_score(findings, assets):

    score = 100

    for finding in findings:

        if "[HIGH]" in finding:
            score -= 20

        elif "[MEDIUM]" in finding:
            score -= 10

        elif "[LOW]" in finding:
            score -= 5

    if assets.get("links", 0) > 20:
        score -= 5

    return max(score, 0)