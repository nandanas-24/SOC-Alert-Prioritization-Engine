def calculate_final_risk(internal_score, abuse_score, occurrences):

    # Internal risk contribution (70%)
    internal_points = min(max(internal_score, 0), 100) * 0.70

    # External IP reputation contribution (20%)
    abuse_points = min(max(abuse_score, 0), 100) * 0.20

    # Duplicate frequency contribution (maximum 10 points)
    duplicate_points = min(max(occurrences - 1, 0) * 5, 10)

    final_score = round(
        internal_points + abuse_points + duplicate_points
    )

    return min(final_score, 100)


def classify_risk(score):

    if score >= 75:
        return "Critical"

    elif score >= 50:
        return "High"

    elif score >= 30:
        return "Medium"

    else:
        return "Low"