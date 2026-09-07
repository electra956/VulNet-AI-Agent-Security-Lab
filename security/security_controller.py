class SecurityController:
    """
    Central security controller for the
    VulNet AI Agent Security Lab.

    Controls:

    - Vulnerable Mode
    - Secure Mode
    - OWASP Agentic AI scenarios
    - Security events
    """

    def __init__(self, mode="secure"):

        self.mode = mode.lower()

        self.events = []


    def set_mode(self, mode):

        mode = mode.lower()

        if mode not in ["secure", "vulnerable"]:

            raise ValueError(
                "Mode must be 'secure' or 'vulnerable'."
            )

        self.mode = mode

        self.log_event(
            "INFO",
            f"Security mode changed to: {mode.upper()}"
        )


    def get_mode(self):

        return self.mode


    def log_event(self, event_type, message):

        event = {
            "type": event_type,
            "message": message
        }

        self.events.append(event)

        return event


    def get_events(self):

        return self.events


    def clear_events(self):

        self.events = []


    def evaluate_request(self, user_request):

        request = user_request.lower()

        suspicious_patterns = [

            "ignore previous instructions",

            "ignore all previous instructions",

            "forget your instructions",

            "change your goal",

            "override your rules",

            "reveal system prompt",

            "execute this instruction",

            "you are now",

        ]

        detected_pattern = None

        for pattern in suspicious_patterns:

            if pattern in request:

                detected_pattern = pattern

                break


        # ----------------------------------------
        # NO SUSPICIOUS PATTERN
        # ----------------------------------------

        if detected_pattern is None:

            self.log_event(
                "INFO",
                "Request passed security validation."
            )

            return {
                "allowed": True,
                "blocked": False,
                "reason": "No suspicious request pattern detected.",
                "scenario": None
            }


        # ----------------------------------------
        # VULNERABLE MODE
        # ----------------------------------------

        if self.mode == "vulnerable":

            self.log_event(
                "WARNING",
                (
                    "ASI01 simulation: suspicious instruction "
                    f"detected but allowed in vulnerable mode: "
                    f"{detected_pattern}"
                )
            )

            return {
                "allowed": True,
                "blocked": False,
                "reason": (
                    "Suspicious instruction allowed for "
                    "controlled educational simulation."
                ),
                "scenario": "ASI01 - Agent Goal Hijack",
                "detected_pattern": detected_pattern
            }


        # ----------------------------------------
        # SECURE MODE
        # ----------------------------------------

        self.log_event(
            "BLOCKED",
            (
                "ASI01 protection blocked suspicious instruction: "
                f"{detected_pattern}"
            )
        )

        return {
            "allowed": False,
            "blocked": True,
            "reason": (
                "Potential Agent Goal Hijack attempt detected."
            ),
            "scenario": "ASI01 - Agent Goal Hijack",
            "detected_pattern": detected_pattern
        }