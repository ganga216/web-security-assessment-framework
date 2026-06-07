def generate_summary(score):

    if score >= 90:
        return "Strong security posture."

    elif score >= 70:
        return "Moderate security posture."

    elif score >= 50:
        return "Security improvements recommended."

    else:
        return "High risk. Immediate remediation required."