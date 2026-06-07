def calculate_score(findings):

    score = 100

    for finding in findings:

        if "[HIGH]" in finding:
            score -= 20

        elif "[MEDIUM]" in finding:
            score -= 10

        elif "[LOW]" in finding:
            score -= 5

    if score < 0:
        score = 0

    return score