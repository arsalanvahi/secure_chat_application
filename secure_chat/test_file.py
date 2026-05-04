from dataclasses import dataclass, field

@dataclass
class User:
    name: str
    scores: list = field(default_factory=list)
u1 = User("Ali")
u2 = User("Bob")
u1.scores.append(10)
print(u1.scores)


