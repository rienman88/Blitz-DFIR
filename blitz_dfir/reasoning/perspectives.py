class PerspectiveReasoning(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firstness: str
    secondness: str
    thirdness: str
    devil_advocate: str

    verdict: str

    confidence: int = Field(
        ge=0,
        le=100,
    )

    carnegie_pattern: str

    next_step: str