import hashlib


class Rotor:
    def __init__(self, seed: str) -> None:
        self.seed = seed
        self.round = 0

    def token(self, family: str) -> str:
        self.round += 1
        return hashlib.sha256(
            f"{self.seed}:{family}:{self.round}".encode()
        ).hexdigest()[:12]

    def sql(self, payload: str, family: str = "sqli-b") -> str:
        tok = self.token(family)
        if "/*" not in payload:
            return payload + f"/*{tok}*/"
        return payload

    def desync_frame(self, kind: str, family: str = "desync") -> str:
        tok = self.token(family)
        if kind == "chunked-ext":
            return f"0;rot={tok}\r\n\r\n"
        return "0\r\n\r\n"

    def smug_header(self, family: str = "desync") -> str:
        return f"X-Rot: {self.token(family)}"