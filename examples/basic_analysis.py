"""Basic example demonstrating the AI-DAC public API."""

from aidac import AIDAC, DatabaseEvent


def main() -> None:
    """Analyse one database-security event."""

    engine = AIDAC()

    event = DatabaseEvent(
        query="DROP TABLE customers;",
        username="application_user",
        database="customer_database",
        source_system="postgresql",
        client_ip="192.168.10.24",
        duration_ms=12.5,
    )

    decision = engine.analyze(event)

    print("AI-DAC Security Analysis")
    print("-" * 50)
    print(f"Event ID: {decision.event_id}")
    print(f"Risk score: {decision.risk_score:.2f}")
    print(f"Severity: {decision.severity.value}")
    print(f"Classification: {decision.classification}")
    print(f"Indicators: {decision.indicators}")
    print(f"Explanation: {decision.explanation}")
    print(f"Recommended action: {decision.recommended_action}")
    print(f"Automatic action: {decision.automatic_action}")


if __name__ == "__main__":
    main()
