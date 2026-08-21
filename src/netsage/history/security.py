"""Defensive secret checks shared by persistent history stores."""

from pydantic import BaseModel

from netsage.security import SecretRedactor


class UnsafeHistoryDataError(ValueError):
    pass


def validated_json(model: BaseModel, redactor: SecretRedactor) -> str:
    serialized = model.model_dump(mode="json")
    if redactor.redact(serialized) != serialized:
        raise UnsafeHistoryDataError("history data contains recognized secret material")
    return model.model_dump_json()
