MESSAGES = []


def save_message(question: str, answer: str) -> None:
    MESSAGES.append((question, answer))
